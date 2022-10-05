import helpers
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EC2
from diagrams.aws.database import RDS
from diagrams.aws.network import ELB

from worker1 import NodeName, Worker1
from worker2 import Worker2

NodeName = "My Threat Model"
class MyCluster(helpers.ThreatModel):
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

    def diagram(self):
        worker1 = Worker1()
        worker2 = Worker2()
        worker2.diagram(),

        with Cluster(self.NodeName):
            (
                ELB(
                    "lb",
                    xlabel=self.render_threats(
                        threats=["DV2", "DV3", "DV4"], remediated_threats=["DV2", "DV3"]
                    ),
                )
                >> Edge(xlabel=self.render_threats(threats=["AC8"]))
                >> [
                    worker1.as_node(),
                    worker2.Interfaces["Worker_2_load_balancer"],
                    EC2(
                        "worker3",
                        xlabel=self.render_threats(
                            threats=["DV2", "DV3", "DV4"],
                            remediated_threats=["DV2", "DV3"],
                        ),
                    ),
                    EC2(
                        "worker4",
                        xlabel=self.render_threats(
                            threats=["DV2", "DV3", "DV4"],
                            remediated_threats=["DV2", "DV3"],
                        ),
                    ),
                    EC2(
                        "worker5",
                        xlabel=self.render_threats(
                            threats=["DV2", "DV3", "DV4"],
                            remediated_threats=["DV2", "DV3"],
                        ),
                    ),
                ]
                >> RDS(
                    "events",
                    xlabel=self.render_threats(
                        threats=["DV2", "DV3", "DV4"],
                        remediated_threats=["DV2", "DV3"],
                    ),
                )
            )

if __name__ == "__main__":
    with Diagram(NodeName, show=False, direction="TB"):
        c = MyCluster()
        c.diagram()
