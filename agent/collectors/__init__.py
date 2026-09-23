from agent.collectors import (agent_self, docker_host, files_triage, logs, network,
                              persistence, processes, resources, velociraptor)

registry = {
    "network": network.collect,
    "processes": processes.collect,
    "persistence": persistence.collect,
    "logs": logs.collect,
    "files_triage": files_triage.collect,
    "containers": docker_host.collect,
    "resources": resources.collect,
    "agent_self": agent_self.collect,
    # On-demand only - deliberately absent from COLLECTOR_ORDER_VOLATILITY_FIRST
    # so an artifact sweep never runs on the routine collection interval.
    "velociraptor": velociraptor.collect,
}
