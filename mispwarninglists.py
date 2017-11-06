#!/usr/bin/env python
import io
import json

from cortexutils.analyzer import Analyzer
from cortexutils.extractor import Extractor
from glob import glob
from os.path import exists


class MISPWarninglistsAnalyzer(Analyzer):
    """
    This analyzer compares given data to the MISP warning lists obtainable via
    https://github.com/MISP/misp-warninglists.
    Configuration options are:

    ```
    MISPWarningLists {
      path = "/path/to/misp-warninglists/repository"  # Default: "misp-warninglists"
    }
    ```
    """
    def __init__(self):
        Analyzer.__init__(self)

        self.data = self.get_data()
        self.path = self.get_param('config.path', 'misp-warninglists')
        if not exists(self.path):
            self.error('Path to misp-warninglists does not exist.')
        self.warninglists = self.readwarninglists()

    def readwarninglists(self):
        files = glob('{}/lists/*/*.json'.format(self.path))
        listcontent = []
        for file in files:
            with io.open(file, 'r') as fh:
                content = json.loads(fh.read())
                values = Extractor().check_iterable(content.get('list', []))
                obj = {
                    "name": content.get('name', 'Unknown'),
                    "values": [value['value'] for value in values],
                    "dataTypes": [value['type'] for value in values]
                }
                listcontent.append(obj)
        return listcontent

    def lastcommit(self):
        try:
            with io.open('{}/.git/refs/heads/master'.format(self.path), 'r') as fh:
                return fh.read()
        except NotADirectoryError as e:
            return 'Could not get commit hash'

    def run(self):
        results = []
        for list in self.warninglists:
            if self.data_type not in list.get('dataTypes'):
                continue

            if self.data in list.get('values', []):
                results.append({
                    "name": list.get('name')
                })

        self.report({
            "results": results,
            "last_update": self.lastcommit()}
        )

    def summary(self, raw):
        taxonomies = []
        if len(raw['results']) > 0:
            taxonomies.append(self.build_taxonomy('suspicious', 'MISP', 'Warninglists', 'Potential fp'))
        else:
            taxonomies.append(self.build_taxonomy('info', 'MISP', 'Warninglists', 'No hits'))

        return {
            "taxonomies": taxonomies
        }


if __name__ == '__main__':
    MISPWarninglistsAnalyzer().run()
