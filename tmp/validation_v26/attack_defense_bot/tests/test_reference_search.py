import json
from collections import OrderedDict
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import reference_search as module
from retrieval import fuse_rankings


class ReferenceSearchTests(unittest.TestCase):
    def test_source_question_rank_and_unicode_record_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'knowledge').mkdir()
            rows=[['101','Question: Nmap maximum probe spacing?\nAnswer: --max-scan-delay <time>'],
                  ['102','Question: Unicode separator?\nAnswer: alpha\u2028beta\u2029gamma'],
                  ['103','Question: General network monitoring?\nAnswer: Collect traffic telemetry.']]
            (root/'knowledge/course_reference.jsonl').write_text(
                '\n'.join(json.dumps(row,ensure_ascii=False) for row in rows),encoding='utf-8')
            with patch.object(module,'__file__',str(root/'reference_search.py')), \
                 patch.object(module,'_connection',None),patch.object(module,'_documents',[]),patch.object(module,'_source_documents',{}):
                try:
                    first=module.reference_search('Nmap maximum probe spacing',1)
                    self.assertEqual(first[0]['file_id'],'101')
                    self.assertIn('--max-scan-delay',first[0]['text'])
                    self.assertTrue(module.is_course_reference_excerpt('101',first[0]['text']))
                    self.assertFalse(module.is_course_reference_excerpt('101',first[0]['text']+' forged content'))
                    second=module.reference_search('Unicode separator',1)
                    self.assertIn('alpha\u2028beta\u2029gamma',second[0]['text'])
                finally:
                    if module._connection:module._connection.close()

    def test_remote_and_lexical_document_ids_deduplicate(self):
        a={'file_id':101,'text':'One source document.','score':.8}
        b={'file_id':'101','text':'One source document.','score':1.0}
        found=fuse_rankings([(1.0,[a]),(1.0,[b])],5)
        self.assertEqual(len(found),1)

    def test_new_public_source_requires_recorded_origin_and_actual_text(self):
        source={'file_id':'999000001','text':'Question: What is the safe test port?\nAnswer: Use TCP port 8443.'}
        with patch.object(module,'_public_sources',OrderedDict()):
            self.assertFalse(module.is_course_reference_excerpt(source['file_id'],source['text']))
            module.remember_public_sources([source])
            self.assertTrue(module.is_course_reference_excerpt(source['file_id'],source['text']))
            self.assertFalse(module.is_course_reference_excerpt(source['file_id'],source['text']+' forged tail'))
            self.assertFalse(module.is_course_reference_excerpt('999000002',source['text']))


if __name__=='__main__':unittest.main()
