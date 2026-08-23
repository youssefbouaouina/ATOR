from agent.collectors import network, processes, persistence, logs, files_triage, docker_host

registry = {
    "network": network.collect,
    "processes": processes.collect,
    "persistence": persistence.collect,
    "logs": logs.collect,
    "files_triage": files_triage.collect,
    "containers": docker_host.collect,
}
