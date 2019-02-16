# Copyright (C) 2016-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import udatetime
import elasticsearch.helpers
import json
import logging
import os
import ujson

from cuckoo.common.abstracts import Report
from cuckoo.common.elastic import elastic
from cuckoo.common.exceptions import CuckooReportError, CuckooOperationalError
from cuckoo.misc import cwd

logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("elasticsearch.trace").setLevel(logging.WARNING)

log = logging.getLogger(__name__)


def flatten_dict(test):
    meta = {}
    meta["test"] = {}
    for item in test:
        if type(test[item]) is dict:
            for values in test[item]:
                if type(test[item][values]) is dict:
                    for second_values in test[item][values]:
                        if type(test[item][values][second_values]) is dict:
                            for third_values in test[item][values][second_values]:
                                if type(test[item][values][second_values][third_values]) is not list or dict or None:
                                    print(type(test[item][values][second_values][third_values]))
                                    debug_test = test[item][values][second_values][third_values]
                                    if debug_test:
                                        meta["test"][str(item + "." + values + "." + second_values + "." + third_values)] = \
                                                str(test[item][values][second_values][third_values])
                        elif type(test[item][values][second_values]) is not list or None:
                            none_test = str(test[item][values][second_values])
                            if none_test:
                                meta["test"][str(item + "." + values + "." + second_values)] = str(test[item][values][second_values])
                elif type(test[item][values]) is not list or None:
                    values_test = test[item][values]
                    if values_test and str(values_test) != "none":
                        meta["test"][str(item + "." + values)] = str(test[item][values])
        elif type(test[item]) is list:
            for list_items in test[item]:
                test_dict = list_items
                if type(test_dict) is str:
                    meta["test"][item] = test_dict
                else:
                    meta[item] = test[item]
        elif type(test[item]) is not list or None:
            test_item = test[item]
            if test_item and str(test_item) != "none":
                meta["test"][item] = test[item]
    return meta


class ElasticSearch(Report):
    """Stores report in Elasticsearch."""

    @classmethod
    def init_once(cls):
        """Connect to Elasticsearch.
        @raise CuckooReportError: if unable to connect.
        """
        # Do not change these types without changing the elasticsearch
        # template as well.
        cls.report_type = "cuckoo"
        cls.call_type = "call"

        if not elastic.init():
            return

        cls.template_name = "%s_template" % elastic.index

        try:
            elastic.connect()
        except CuckooOperationalError as e:
            raise CuckooReportError(
                "Error running ElasticSearch reporting module: %s" % e
            )

        # check to see if the template exists apply it if it does not
        if not elastic.client.indices.exists_template(cls.template_name):
            if not cls.apply_template():
                raise CuckooReportError("Cannot apply Elasticsearch template")

    @classmethod
    def apply_template(cls):
        template_path = cwd("elasticsearch", "template.json")
        if not os.path.exists(template_path):
            return False

        try:
            template = json.loads(open(template_path, "rb").read())
        except ValueError:
            raise CuckooReportError(
                "Unable to read valid JSON from the ElasticSearch "
                "template JSON file located at: %s" % template_path
            )

        # Create an index wildcard based off of the index name specified
        # in the config file, this overwrites the settings in
        # template.json.
        template["template"] = elastic.index + "-*"

        # if the template does not already exist then create it
        if not elastic.client.indices.exists_template(cls.template_name):
            try:
                elastic.client.indices.put_template(name=cls.template_name, body=ujson.dumps(template))
            except Exception as e:
                elastic.client.indices.put_template(name=cls.template_name, body=json.dumps(template))
        return True

    def get_base_document(self):
        # Gets precached report time and the task_id.
        header = {
            "task_id": self.task["id"],
            "report_time": self.report_time,
            "report_id": self.task["id"]
        }
        return header

    def do_index(self, obj):
        base_document = self.get_base_document()

        # Append the base document to the object to index.
        base_document.update(obj)

        try:
            elastic.client.index(
                index=self.dated_index,
                doc_type=self.report_type,
                body=base_document
            )
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def do_bulk_index(self, bulk_reqs):
        try:
            elasticsearch.helpers.bulk(elastic.client, bulk_reqs)
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def process_info(self, report):
        value = flatten_dict(report)
        meta = value["test"]
        return meta


    def run(self, results):
        """Index the Cuckoo report into ElasticSearch.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if the connection or reporting failed.
        """
        # Gets the time which will be used for indexing the document into ES
        # ES needs epoch time in seconds per the mapping
        self.report_time = udatetime.utcnow_to_string()

        # Get the index time option and set the dated index accordingly
        date_index = udatetime.utcnow().strftime({
            "yearly": "%Y",
            "monthly": "%Y-%m",
            "daily": "%Y-%m-%d",
        }[elastic.index_time_pattern])
        self.dated_index = "%s-%s" % (elastic.index, date_index)

        # Index target information, the behavioral summary, and
        # VirusTotal results.

        # index elements that are not empty ES should not index blank fields

        doc = self.process_info(results)
        doc["cuckoo_node"] = elastic.cuckoo_node

        self.do_index(doc)

        # Index the API calls.
