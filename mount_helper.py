#!/root/miniconda2/bin/python
import base64
import json
import os
import sys
from cryptography.fernet import Fernet
from fs.contrib.davfs import DAVFS
from fs.mountfs import MountFS
from fs.expose import fuse
import girder_client
from girderfs.core import LocalGirderFS

GIRDER_API_URL = os.environ.get(
    "GIRDER_API_URL", "https://girder.hub.yt/api/v1")
OWNCLOUD_URL = os.environ.get(
    "OWNCLOUD_URL", "https://owncloud.hub.yt")
HOSTDIR = os.environ.get("HOSTDIR", "/host")

gc = girder_client.GirderClient(apiUrl=GIRDER_API_URL)
gc.authenticate(apiKey=sys.argv[1])

# create home
payload = gc.get('/user/ocpass')
key = base64.b64encode(gc.token[:32].encode('utf8'))
creds = Fernet(key).decrypt(payload['credentials'].encode('utf8'))
oc = DAVFS(OWNCLOUD_URL + '/remote.php/webdav',
           credentials=json.loads(creds.decode('utf8')))
data = LocalGirderFS(sys.argv[2], gc)

combined_fs = MountFS()
combined_fs.mountdir('data/', data)
combined_fs.mountdir('home', oc)

fuse.mount(combined_fs, sys.argv[3], allow_other=True, foreground=False)
