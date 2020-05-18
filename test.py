import cofense

triage = cofense.triage(email='ryan.jones@cofense.com', key="bd27729c6f3d3cd1a5d09613434ba321", host="https://192.168.0.72", strictssl=False)

#print(triage.categories(cat_id=4))
print(triage.clusters(bulk_results=51))

