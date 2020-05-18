Quick Start
===========
For the most part the endpoint names have been preserved. If the endpoint was clusters than it's still called clusters.
The same goes for the parameters (mostly).

CPM will try and throw useful exceptions where you've made a mistake, but this is still very much a work in progress.

.. code-block:: python
   :linenos:

    import cofense
    triage = cofense.triage(email='ryan.jones@cofense.com', key="bd27729c6f3d3cd1a5d09613434ba321", host="https://192.168.0.72", strictssl=False)
    print(triage.clusters(cluster_id=21))