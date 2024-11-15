#!/usr/bin/env python3

import argparse
import elasticsearch
import os
import signal
import sys
import logging

from schema import Optional, Or, Schema, SchemaError


def parse_arguments():
    """parse arguments"""

    parser = argparse.ArgumentParser(description="ILM Limiter")
    parser.add_argument(
        "--url",
        type=str,
        help="url with protocol and port (falls back to env var ELASTICSEARCH_HOST)",
        default=os.environ.get("ELASTICSEARCH_HOST"),
        required="ELASTICSEARCH_HOST" not in os.environ.keys(),
    )
    parser.add_argument(
        "--username",
        type=str,
        help="username (falls back to env var ELASTICSEARCH_AUTH_USR)",
        default=os.environ.get("ELASTICSEARCH_AUTH_USR"),
        required="ELASTICSEARCH_AUTH_USR" not in os.environ.keys(),
    )
    parser.add_argument(
        "--password",
        type=str,
        help="password (falls back to env var ELASTICSEARCH_AUTH_PSW)",
        default=os.environ.get("ELASTICSEARCH_AUTH_PSW"),
        required="ELASTICSEARCH_AUTH_PSW" not in os.environ.keys(),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="enable dry-run mode",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="enable debug logs",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="custom request timeout for elasticsearch",
        default=None,
    )

    return parser.parse_args()


def configure_logging(debug: bool):
    """configure logging format and level"""

    logging.basicConfig(format="%(levelname)s - %(message)s", level=logging.DEBUG if debug else logging.INFO)

    logging.getLogger("elastic_transport.transport").level = logging.DEBUG if debug else logging.ERROR
    logging.getLogger("urllib3.connectionpool").level = logging.ERROR


def convert_size_to_bytes(size: str) -> int:
    """Convert bytes with units to bytes."""

    units = ["kb", "mb", "gb", "tb"]
    factor = 1024

    for step, unit in enumerate(units):
        if size.lower().endswith(unit):
            return int(float(size[0 : -len(unit)]) * (factor ** (step + 1)))

    raise ValueError("could not convert '{}' to bytes".format(size))


def convert_bytes_to_size(bytes: int) -> str:
    """Convert bytes to bytes with units."""

    units = ["b", "kb", "mb", "gb", "tb"]
    factor = 1024

    step = 0
    while bytes >= factor and step < len(units) - 1:
        step += 1
        bytes /= factor

    return "{:.2f}{}".format(bytes, units[step])


class Ilm_limiter:
    # ILM phases in their actual order, the last phase in this list will be ignored
    global_lifecycle_phases = ["hot", "warm", "cold", "frozen", "delete"]

    cluster_privileges = ["manage", "manage_ilm"]
    index_privileges = ["manage"]

    def __init__(self, elasticsearch_client: elasticsearch.Elasticsearch, dry_run=False):
        self.es = elasticsearch_client
        self.dry_run = dry_run

    def check_cluster_privileges(self):
        """check required cluster privileges"""

        privileges = self.es.security.has_privileges(cluster=self.cluster_privileges)
        logging.debug("cluster privileges: {}".format(privileges))

        if not privileges["has_all_requested"]:
            raise ValueError("user is missing cluster privileges {}".format(self.cluster_privileges))

    def check_index_privileges(self, indexes: list[str]):
        """check required index privileges"""

        if indexes:
            privileges = self.es.security.has_privileges(index=[{"names": indexes, "privileges": self.index_privileges}])
            logging.debug("index privileges: {}".format(privileges))

            if not privileges["has_all_requested"]:
                raise ValueError("user is missing index privileges {} on {}".format(self.index_privileges, indexes))

    def run_limits(self):
        """run limiter on applicable lifecycles"""

        # ensure we have required privileges for moving indexes
        self.check_cluster_privileges()

        # get lifecycles that have an ilm-limiter configuration
        lifecycles = self.get_lifecycles()

        # check lifecycles one by one
        for lifecycle_name, lifecycle_properties in lifecycles.items():
            try:
                self.check_lifecycle(lifecycle_name, lifecycle_properties)
            except ValueError as e:
                logging.error(e)

        # log summary of all configured limits
        self.log_lifecycle_stats(lifecycles)

    def log_lifecycle_stats(self, lifecycles: dict):
        """create a summary of all configured limits"""

        phases = {}

        for lifecycle_properties in lifecycles.values():
            for lifecycle_phase_name, lifecycle_phase_properties in lifecycle_properties["policy"]["phases"].items():
                if "limits" in lifecycle_phase_properties:
                    phases.setdefault(lifecycle_phase_name, 0)
                    phases[lifecycle_phase_name] += lifecycle_phase_properties["limits"]["max_size_bytes"]

        for phase, limit in sorted(phases.items(), key=lambda p: self.global_lifecycle_phases.index(p[0])):
            logging.info("sum of limits on all lifecycle phases '{}': {}".format(phase, convert_bytes_to_size(limit)))

    def get_lifecycles(self) -> dict:
        """return all lifecycles that have an ilm-limiter configuration"""

        lifecycles = self.es.ilm.get_lifecycle()

        lifecycles_filtered = {
            lifecycle_name: self.decode_lifecycle_phases(lifecycle_name, lifecycle_properties)
            for lifecycle_name, lifecycle_properties in lifecycles.items()
            if self.is_lifecycle_limited(lifecycle_name, lifecycle_properties)
        }

        return lifecycles_filtered

    def is_lifecycle_limited(self, lifecycle_name: str, lifecycle_properties: dict) -> bool:
        """verify if a lifecycle has a valid ilm-limiter configuration in its _meta object"""

        schema = Schema(
            {
                "_meta": {
                    "ilm-limiter": {"phases": {str: {"max_size": convert_size_to_bytes}}},
                    Optional(str): Or(dict, str, list),
                },
                "phases": dict,
            }
        )

        try:
            schema.validate(lifecycle_properties["policy"])
            logging.debug("lifecycle '{}' has a valid ilm-limiter configuration".format(lifecycle_name))
            return True
        except SchemaError as e:
            logging.debug("lifecycle '{}' has a no valid ilm-limiter configuration ({})".format(lifecycle_name, e))
            return False

    def decode_lifecycle_phases(self, lifecycle_name: str, lifecycle_properties: dict) -> dict:
        """merge lifecycle limits from _meta object with their phases"""

        # limits from lifecycle '_meta'
        lifecycle_phases_limits = lifecycle_properties["policy"]["_meta"]["ilm-limiter"]["phases"]

        for phase, limits in lifecycle_phases_limits.items():
            if phase in lifecycle_properties["policy"]["phases"]:
                # extend limits object with max_size converted to bytes
                limits_extended = limits | {"max_size_bytes": convert_size_to_bytes(limits["max_size"])}
                lifecycle_properties["policy"]["phases"][phase]["limits"] = limits_extended
            else:
                logging.warning("lifecycle '{}' has no phase '{}' but limits".format(lifecycle_name, phase))

        return lifecycle_properties

    def check_lifecycle(self, lifecycle_name: str, lifecycle_properties: dict):
        """check all phases of a lifecycle"""

        logging.info("check lifecycle '{}'".format(lifecycle_name))

        # get indexes using the lifecycle
        lifecycle_indexes = lifecycle_properties["in_use_by"]["indices"]

        # ensure we have required privileges for moving indexes
        self.check_index_privileges(lifecycle_indexes)

        # get indexes in lifecycle grouped by phases
        lifecycle_phases_indexes = self.get_indexes_in_phases(lifecycle_indexes)

        # filter for the phases we know about / know their order
        lifecycle_phases = {
            lifecycle_phase_name: lifecycle_phase_properties
            for lifecycle_phase_name, lifecycle_phase_properties in lifecycle_properties["policy"]["phases"].items()
            if lifecycle_phase_name in self.global_lifecycle_phases[:-1]
        }

        # go over known phases in reverse order
        for lifecycle_phase_name, lifecycle_phase_properties in sorted(
            lifecycle_phases.items(), key=lambda p: self.global_lifecycle_phases.index(p[0]), reverse=True
        ):
            # check if phase has limits configured
            if "limits" in lifecycle_phase_properties:
                lifecycle_phase_limits = lifecycle_phase_properties["limits"]
                lifecycle_phase_indexes = lifecycle_phases_indexes.get(lifecycle_phase_name, {})
                lifecycle_phase_next = self.get_next_lifecycle_phase(lifecycle_properties, lifecycle_phase_name)

                logging.info(
                    "lifecycle '{}', phase '{}' is limited to {}, next phase: '{}'".format(
                        lifecycle_name, lifecycle_phase_name, lifecycle_phase_limits["max_size"], lifecycle_phase_next
                    )
                )
                self.check_lifecycle_phase(
                    lifecycle_name,
                    lifecycle_phase_name,
                    lifecycle_phase_next,
                    lifecycle_phase_limits,
                    lifecycle_phase_indexes,
                )
            else:
                logging.info("lifecycle '{}', phase '{}' is not limited".format(lifecycle_name, lifecycle_phase_name))

    def get_next_lifecycle_phase(self, lifecycle_properties: dict, current_phase: str) -> str:
        """for the given 'current phase', determine the next phase in the lifecycle policy"""

        index_current_phase = self.global_lifecycle_phases.index(current_phase)
        for phase in self.global_lifecycle_phases[index_current_phase + 1 :]:
            if phase in lifecycle_properties["policy"]["phases"]:
                return phase

        raise ValueError("cannot determine successor of phase '{}'".format(current_phase))

    def check_lifecycle_phase(
        self, lifecycle_name: str, lifecycle_phase: str, lifecycle_phase_next: str, lifecycle_phase_limit: dict, lifecycle_phase_indexes: dict
    ):
        """check all indexes in a phase"""

        disk_usage_phase_limit = lifecycle_phase_limit["max_size_bytes"]
        disk_usage_phase_sum = 0

        # iterate over indexes in reverse chronological order
        for index_name, index_current_ilm_step in sorted(
            lifecycle_phase_indexes.items(),
            key=lambda item: self.get_index_lifecycle_date(item[0]),
            reverse=True,
        ):
            disk_usage_index = self.get_index_total_dataset_size(index_name)
            disk_usage_phase_sum += disk_usage_index

            logging.info(
                "lifecycle '{}', phase '{}', index '{}': usage={}, total={}, limit={}".format(
                    lifecycle_name,
                    lifecycle_phase,
                    index_name,
                    convert_bytes_to_size(disk_usage_index),
                    convert_bytes_to_size(disk_usage_phase_sum),
                    convert_bytes_to_size(disk_usage_phase_limit),
                )
            )

            # check if summed up index disk usage exceeds the limit
            if disk_usage_phase_sum > disk_usage_phase_limit:

                # check if index is in the final state of the current phase
                if index_current_ilm_step["action"] == "complete" and index_current_ilm_step["name"] == "complete":
                    logging.info(
                        "lifecycle '{}', phase '{}', index '{}' is moved to phase '{}'{}".format(
                            lifecycle_name,
                            lifecycle_phase,
                            index_name,
                            lifecycle_phase_next,
                            " (DRY-RUN)" if self.dry_run else "",
                        )
                    )

                    if not self.dry_run:
                        try:
                            self.es.ilm.move_to_step(index=index_name, current_step=index_current_ilm_step, next_step={"phase": lifecycle_phase_next})
                        except elasticsearch.BadRequestError as e:
                            # catch when ILM has moved or deleted the index just now (may happen when ilm-limiter runs at the same time as ILM)
                            logging.error("index got moved or deleted: {}".format(e))

                else:
                    logging.error(
                        "lifecycle '{}', phase '{}', index '{}' cannot be moved as it is in a non-steady step: {}".format(
                            lifecycle_name, lifecycle_phase, index_name, index_current_ilm_step
                        )
                    )

    def get_indexes_in_phases(self, index_names: list) -> dict:
        """divide indexes into their phases"""

        phases = {}

        for index_name in index_names:
            index_current_ilm_step = self.get_index_current_ilm_step(index_name)

            logging.debug("index '{}' current ilm step: {}".format(index_name, index_current_ilm_step))

            phases.setdefault(index_current_ilm_step["phase"], {})[index_name] = index_current_ilm_step

        return phases

    def get_index_current_ilm_step(self, index_name: str) -> dict:
        """get current ilm phase, action and step of an index"""

        ilm = self.es.ilm.explain_lifecycle(index=index_name)
        ilm_phase = ilm["indices"][index_name]["phase"]
        ilm_action = ilm["indices"][index_name]["action"]
        ilm_step = ilm["indices"][index_name]["step"]

        index_current_ilm_step = {
            "phase": ilm_phase,
            "action": ilm_action,
            "name": ilm_step,
        }

        return index_current_ilm_step

    def get_index_creation_date(self, index_name: str) -> int:
        """get creation date of an index"""

        settings = self.es.indices.get_settings(index=index_name)
        index_creation_date = int(settings[index_name]["settings"]["index"]["creation_date"])
        logging.debug("index '{}' creation date: {}".format(index_name, index_creation_date))

        return index_creation_date

    def get_index_lifecycle_date(self, index_name: str) -> int:
        """get lifecycle date of an index (before rollover that is the creation date, otherwise the rollover date)"""

        explain = self.es.ilm.explain_lifecycle(index=index_name)
        index_lifecycle_date = int(explain["indices"][index_name]["lifecycle_date_millis"])
        logging.debug("index '{}' lifecycle date: {}".format(index_name, index_lifecycle_date))

        return index_lifecycle_date

    def get_index_total_dataset_size(self, index_name: str) -> int:
        """get total dataset size of an index"""

        shards = self.es.cat.shards(index=index_name, format="json", bytes="b")
        index_disk_usage = sum(int(shard["dataset"] or 0) for shard in shards)
        logging.debug("index '{}' disk usage: {}".format(index_name, index_disk_usage))

        return index_disk_usage


def signal_handler(signum, frame):
    print(f"Received signal {signal.Signals(signum).name} ({signum})")


def main():
    # configure signal handler to continue the process when receiving SIGTERM
    signal.signal(signal.SIGTERM, signal_handler)

    # parse arguments
    args = parse_arguments()

    # configure logging
    configure_logging(debug=args.debug)

    # connect to elasticsearch
    try:
        es = elasticsearch.Elasticsearch(args.url, basic_auth=(args.username, args.password), request_timeout=args.timeout, headers={"X-Caller": "ilm-limiter"})
    except ValueError as e:
        logging.error("elasticsearch ({}): {}".format(args.url, e))
        return 1

    # create and run limiter
    try:
        limiter = Ilm_limiter(es, args.dry_run)
        limiter.run_limits()
    except ValueError as e:
        logging.error(e)
        return 1
    except (elasticsearch.AuthenticationException, elasticsearch.ConnectionError, elasticsearch.ConnectionTimeout) as e:
        logging.error("elasticsearch ({}): {}".format(args.url, e))
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
