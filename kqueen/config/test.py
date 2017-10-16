DEBUG = True

# Demo login
USERNAME = 'admin'
PASSWORD = 'default'

# App secret
SECRET_KEY = 'secret'

# Cluster statuses
CLUSTER_ERROR_STATE = 'Error'
CLUSTER_OK_STATE = 'OK'
CLUSTER_PROVISIONING_STATE = 'Deploying'
CLUSTER_DEPROVISIONING_STATE = 'Destroying'
CLUSTER_UNKNOWN_STATE = 'Unknown'

# Provisioner statuses
PROVISIONER_ERROR_STATE = 'Error'
PROVISIONER_OK_STATE = 'OK'
PROVISIONER_UNKNOWN_STATE = 'Not Reachable'

# Jenkins engine settings
JENKINS_API_URL = 'http://localhost'
JENKINS_PROVISION_JOB_NAME = 'job_name'
JENKINS_PROVISION_JOB_CTX = {}
JENKINS_ANCHOR_PARAMETER = 'STACK_NAME'
JENKINS_USERNAME = None
JENKINS_PASSWORD = None
