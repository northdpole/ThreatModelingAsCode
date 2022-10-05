import helpers
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EC2
from diagrams.aws.database import RDS
from diagrams.aws.network import ELB

NodeName = "Worker 2"


class Worker2(helpers.ThreatModel):
    def __init__(self) -> None:
        super().__init__()
        self.NodeName = NodeName
        self.Threats = [
            "DV2",
            "DV3",
            "DV4",
            "AC8",
        ]
        self.Remediated = [
            "DV2",
            "DV3",
        ]

        self.add_external_interface(
            "Worker_2_load_balancer",
        )

    def diagram(self):
        with Cluster(self.NodeName):

            (
                self.Interfaces["Worker_2_load_balancer"]
                >> ELB(
                    "load balancer",
                    xlabel=self.render_threats(
                        threats=["DV2", "DV3", "DV4"],
                        remediated_threats=["DV2", "DV3"],
                    ),
                )
                >> Edge(label=self.render_threats(threats=["AC8"]))
                >> EC2(
                    "worker2",
                    xlabel=self.render_threats(
                        threats=["DV2", "DV3", "DV4"], remediated_threats=["DV2", "DV3"]
                    ),
                )
                >> RDS(
                    "events",
                    xlabel=self.render_threats(
                        threats=["DV2", "DV3", "DV4"], remediated_threats=["DV2", "DV3"]
                    ),
                )
            )


if __name__ == "__main__":
    with Diagram(NodeName, show=False, direction="TB"):
        c = Worker2()
        c.diagram()
