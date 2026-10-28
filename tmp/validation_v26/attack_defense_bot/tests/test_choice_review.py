import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from main import verify_choice
from config import load_settings

class ChoiceReviewTests(unittest.TestCase):
    def test_permutation_votes_map_back_to_original_options(self):
        question='Which protects confidentiality?\nA. Encryption\nB. Deletion\nC. Guessing\nD. None'
        client=Mock();client.dialogue.side_effect=[
            '{"decision":"answer","answer":"D","evidence":[]}',
            '{"decision":"answer","answer":"D","evidence":[]}']
        draft='{"decision":"answer","answer":"A","evidence":[]}'
        result=verify_choice(question,draft,'',[],client,load_settings(),strategy='consistency')
        self.assertEqual(json.loads(result)['answer'],'A')
        self.assertEqual(client.dialogue.call_count,2)

    def test_disagreement_is_reviewed_without_using_labels(self):
        question='Which protects confidentiality?\nA. Encryption\nB. Deletion\nC. Guessing\nD. None'
        client=Mock()
        client.dialogue.side_effect=[
            '{"decision":"answer","answer":"A","evidence":[],"explanation":"Encryption protects confidentiality."}',
            '{"decision":"answer","answer":"A","evidence":[1],"explanation":"The source supports encryption."}']
        draft='{"decision":"answer","answer":"B","evidence":[1],"explanation":"initial candidate"}'
        result=verify_choice(question,draft,'Encryption protects confidentiality.',['[1] source'],client,load_settings())
        self.assertEqual(json.loads(result)['answer'],'A')
        self.assertEqual(client.dialogue.call_count,2)
        self.assertIn('DRAFT_ANSWER',client.dialogue.call_args.kwargs['custom_prompt'])

if __name__=='__main__':unittest.main()
