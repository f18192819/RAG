import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from question_format import has_choice_options, choice_stem

class QuestionFormatTests(unittest.TestCase):
    def test_equivalent_option_formats(self):
        for options in ['A. first\nB. second','A . first\nB . second','a。 first\nb。 second',
                        '(A) first (B) second','Ａ：first\nＢ：second']:
            question='Which is correct?\n'+options
            self.assertTrue(has_choice_options(question))
            self.assertEqual(choice_stem(question),'Which is correct?')

    def test_ordinary_security_text_is_not_a_choice(self):
        self.assertFalse(has_choice_options('Explain API key rotation and TLS 1.3.'))

if __name__=='__main__':unittest.main()
