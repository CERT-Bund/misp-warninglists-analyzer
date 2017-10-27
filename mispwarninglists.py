#!/usr/bin/env python
from cortexutils.analyzer import Analyzer
from glob import glob
import io
import json

class MISPWarninglistsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        if self.get_param('config.enablepull', True):
            self.__pullrepo()

        self.data = self.getData()
        self.warninglists = self.__readwarninglists()

    def __pullrepo(self):
        # Todo: Implement git pulling instead of clonings, if repo is already cloned
        import pygit2
        from shutil import rmtree
        from os.path import exists

        if exists('misp-warninglists'):
            rmtree('misp-warninglists')

        pygit2.clone_repository('https://github.com/MISP/misp-warninglists', 'misp-warninglists')

    def __readwarninglists(self):
        files = glob('misp-warninglists/lists/*/*.json')
        listcontent = []
        for file in files:
            with io.open(file, 'r') as fh:
                content = json.loads(fh.read())
                obj = {
                    "name": content.get('name', 'Unknown'),
                    "values": content.get('list', []),
                    "dataTypes": []
                }
                for type in content.get('matching_attributes', []):
                    if type in ['md5', 'sha1', 'sha256', 'ssdeep']:
                        obj['dataTypes'].append('hash')
                        continue
                    if 'filename|' in type:
                        obj['dataTypes'].append('hash')
                        continue
                    if 'ip' in type:
                        obj['dataTypes'].append('ip')
                        continue
                    if 'domain' in type:
                        obj['dataTypes'].append('domain')
                    if 'url' in type:
                        obj['dataTypes'].append('url')
                listcontent.append(obj)
        return listcontent

    def run(self):
        results = []
        for list in self.warninglists:
            if self.data_type not in list.get('dataTypes'):
                continue

            if self.data in list.get('values', []):
                results.append({
                    'name': list.get('name')
                })
        self.report(results)

    def summary(self, raw):
        taxonomies = []
        if len(raw) > 0:
            taxonomies.append(self.build_taxonomy('suspicious', 'MISP', 'Warninglists', 'Potential fp'))
        else:
            taxonomies.append(self.build_taxonomy('info', 'MISP', 'Warninglists', 'No hits'))

        return {
            "taxonomies": taxonomies
        }

if __name__ == '__main__':
    MISPWarninglistsAnalyzer().run()
