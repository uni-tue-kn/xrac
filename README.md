# xRAC
xRAC implements execution and network access control for restricted application containers (RACs) using 802.1X. The research paper "xRAC: Execution and Access Control for Restricted Application Containers on Managed Hosts" ([preprint on arXiv](https://arxiv.org/abs/1907.03544)) was accepted for the main technical track of [NOMS 2020](https://noms2020.ieee-noms.org/). In addition, we submitted a demo paper that is currently under review.

Contents of this repository:

* [Testbed setup guide](testbed-setup.md)
* [Experiment instructions](experiments.md)
* Source code
  * 802.1X CS (in folder `xrac-cs`)
  * 802.1X CA (in folder `xrac-ca`)
* Configuration files for the 802.1X AS (in folder `xrac-as`).

Please be aware of the **following legal conditions**:

```
(1) We hereby prohibit any commercial usage of the contents provided with this repository. Please note, that the functionality of this prototypical implementation of xRAC is part of an ongoing patent application process.

(2) The software and configuration examples are provided "as is" without any warranty of any kind.

Copyright (c) 2020 University of Tuebingen, Faculty of Science, Department of Computer Science, Chair of Communication Networks.
```