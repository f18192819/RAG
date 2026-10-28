import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from question_format import has_choice_options, choice_stem, is_chinese_question

class QuestionFormatTests(unittest.TestCase):
    def test_equivalent_option_formats(self):
        for options in ['A. first\nB. second','A . first\nB . second','a。 first\nb。 second',
                        '(A) first (B) second','Ａ：first\nＢ：second']:
            question='Which is correct?\n'+options
            self.assertTrue(has_choice_options(question))
            self.assertEqual(choice_stem(question),'Which is correct?')

    def test_ordinary_security_text_is_not_a_choice(self):
        self.assertFalse(has_choice_options('Explain API key rotation and TLS 1.3.'))

    def test_headers_do_not_change_language_or_technical_expression(self):
        self.assertEqual(choice_stem('【简答题】\n问题：What is 1+1?'),'What is 1+1?')
        self.assertFalse(is_chinese_question('题目：What is TLS?（术语）'))
        self.assertTrue(is_chinese_question('问题：TLS与RSA的核心安全目标是什么？'))

if __name__=='__main__':unittest.main()
