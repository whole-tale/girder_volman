import girder_client
import docker
import libmount
import os
import tangelo

LOCAL_SOURCE = "/home/yt"

TEST_FOLDER = "56f9583e37c29f0001667d48"

def get_list_sources(folder):
    print("Getting folders from collection")
    gc = girder_client.GirderClient(apiUrl='https://hub.yt/girder/api/v1')
    source = [item["name"] for item in 
              gc.listFolder(folder, parentFolderType='collection')]
    return source

def get_image(image_name, image_tag="latest"):
    dcli = docker.Client()
    repo_tag = image_name + ":" + image_tag
    for image in dcli.images():
        if repo_tag in image['RepoTags']:
            return image
    return None

@tangelo.types(folder=str)
def run(folder=""):
    tangelo.content_type("text/plain")
    #print("Creating volume container")
    dcli = docker.Client()
    image = get_image("ubuntu")
    vol_container = dcli.create_container(
        image['Id'], ['/bin/true'],
        name="test",
        volumes=["/mnt/yt"],
    )

    data = dcli.inspect_container(vol_container['Id'])
    path = data["Mounts"][0]["Source"]

    #print("Mount binding folders")
    for directory in get_list_sources(TEST_FOLDER):
        target = os.path.join(path, directory)
        os.mkdir(target)
        cx = libmount.Context()
        cx.fstype = "bind"
        cx.options = "bind"
        cx.target = "{}".format(target)
        cx.source = "{}".format(os.path.join("/home/yt", directory))
        cx.mount()

    #print("Creating final container")
    exec_container = dcli.create_container(
        image['Id'], ['/bin/sleep', 'infinity'],
        name="test_run",
    )

    #print("Starting container")
    dcli.start(
        exec_container['Id'],
        volumes_from=vol_container['Id'],
    )

    return "docker exec -ti {} /bin/bash\n".format(exec_container['Id'][:8])
