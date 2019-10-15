# Imports the Openstack client library
import logging
from swiftclient import Connection
from cuckoo.common.abstracts import Report
from os import walk, environ
log = logging.getLogger("cuckoo")


class SwiftConnection(object):
    order = 2

    def __init__(self):
        # Read configuration from environment variables (openstack.rc)
        auth_url = environ["OPENSTACK_AUTH_URL"]
        user_domain_name = environ["OPENSTACK_USER_DOMAIN_NAME"]
        user_name = environ["OPENSTACK_USERNAME"]
        password = environ["OPENSTACK_PASSWORD"]
        project_domain_name = environ["OPENSTACK_PROJECT_DOMAIN_NAME"]
        project_name = environ["OPENSTACK_PROJECT_NAME"]
        container_name = environ["OPENSTACK_CONTAINER_NAME"]
        ca_certificate = environ["OPENSTACK_CA_CERTIFICATE"]
        self.container_name = container_name
        options = {
            'user_domain_name': user_domain_name,
            'project_domain_name': project_domain_name,
            'project_name': project_name,
        }
        # Establish the connection with the object storage API cacert=ca_certificate,
        self.conn = Connection(
            user=user_name,
            key=password,
            authurl=auth_url,
            auth_version=3,
            os_options=options,
            cacert=ca_certificate,
            timeout=120
        )
        found = False
        for container in self.conn.get_account()[1]:
            cname = container['name']
            if cname == container_name:
                found = True
        if found is not True:
            # Create a new container
            container_name = container_name
            self.conn.put_container(container_name)

    def put(self, file_name, file_content):
        """Upload file object to swift bucket."""
        container_name = self.container_name
        self.conn.put_object(container_name, file_name, contents=file_content, )

    def get_file(self, file_name):
        """Download file object from swift bucket."""
        container_name = self.container_name
        self.conn.get_object(container_name, file_name)


class ObjectStroage(Report):
    def run(self, results):
        report_id = str(results["info"]["id"])
        report_storage_path = str(environ["CUCKOO_STORAGE_PATH"])
        report_file_path = str(report_storage_path) + str(report_id) + "/"

        file_path = report_file_path
        file_list = []

        for (dir_path, dir_names, file_names) in walk(file_path):
            file_list.extend(file_names)
            break
        swift = SwiftConnection()
        for items in file_list:
            with open(str(file_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/" + items), file_content=swift_file_object)

        report_file_list = []
        report_path = report_file_path + "reports/"
        for (dir_path, dir_names, file_names) in walk(report_path):
            report_file_list.extend(file_names)
            break

        for items in report_file_list:
            with open(str(report_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/reports/" + items), file_content=swift_file_object)

        buffer_file_list = []
        buffer_path = report_file_path + "buffer/"
        for (dir_path, dir_names, file_names) in walk(buffer_path):
            buffer_file_list.extend(file_names)
            break

        for items in buffer_file_list:
            with open(str(buffer_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/buffer/" + items), file_content=swift_file_object)

        extracted_file_list = []
        extracted_path = report_file_path + "extracted/"
        for (dir_path, dir_names, file_names) in walk(extracted_path):
            extracted_file_list.extend(file_names)
            break

        for items in extracted_file_list:
            with open(str(extracted_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/extracted/" + items), file_content=swift_file_object)

        files_file_list = []
        files_path = report_file_path + "files/"
        for (dir_path, dir_names, file_names) in walk(files_path):
            files_file_list.extend(file_names)
            break

        for items in files_file_list:
            with open(str(files_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/files/" + items), file_content=swift_file_object)

        logs_file_list = []
        logs_path = report_file_path + "logs/"
        for (dir_path, dir_names, file_names) in walk(logs_path):
            logs_file_list.extend(file_names)
            break

        for items in logs_file_list:
            with open(str(logs_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/logs/" + items), file_content=swift_file_object)

        shots_file_list = []
        shots_path = report_file_path + "shots/"
        for (dir_path, dir_names, file_names) in walk(shots_path):
            shots_file_list.extend(file_names)
            break

        for items in shots_file_list:
            with open(str(shots_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/shots/" + items), file_content=swift_file_object)

        network_file_list = []
        network_path = report_file_path + "network/"
        for (dir_path, dir_names, file_names) in walk(network_path):
            network_file_list.extend(file_names)
            break

        for items in network_file_list:
            with open(str(network_path + items), 'rb') as swift_file:
                swift_file_object = swift_file.read()
            swift.put(file_name=str(report_id + "/network/" + items), file_content=swift_file_object)
