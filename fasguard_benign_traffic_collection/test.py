# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import os
import traceback
import unittest

class TAPTestResult(unittest.TestResult):
    def stopTestRun(self):
        super(TAPTestResult, self).stopTestRun()
        print '1..' + str(self.testsRun)

    def _print_line(self, status, test, directive=None):
        if directive is None:
            directive = ''
        else:
            directive = '# ' + directive
        print \
            status, \
            str(self.testsRun), \
            test.shortDescription() or str(test), \
            directive

    def _print_bad(self, test, err):
        self._print_line('not ok', test)
        tb = traceback.format_exception(*err)
        for line in ''.join(tb).splitlines():
            print '#', line

    def _print_exp(self, test, ok):
        testMethod = getattr(test, test._testMethodName)
        note = getattr(testMethod, '__taptest_expected_failure_note__',
                       '(unexpected success)' if ok else '(expected failure)')
        self._print_line('ok' if ok else 'not ok', test, 'TODO ' + note)

    def addError(self, test, err):
        super(TAPTestResult, self).addError(test, err)
        self._print_bad(test, err)

    def addFailure(self, test, err):
        super(TAPTestResult, self).addFailure(test, err)
        self._print_bad(test, err)

    def addSuccess(self, test):
        super(TAPTestResult, self).addSuccess(test)
        self._print_line('ok', test)

    def addSkip(self, test, reason):
        super(TAPTestResult, self).addSkip(test, reason)
        self._print_line('ok', test, 'SKIP ' + str(reason))

    def addExpectedFailure(self, test, err):
        super(TAPTestResult, self).addExpectedFailure(test, err)
        self._print_exp(test, False)

    def addUnexpectedSuccess(self, test):
        super(TAPTestResult, self).addUnexpectedSuccess(test)
        self._print_exp(test, True)

class TAPTestRunner(unittest.TextTestRunner):
    resultclass = TAPTestResult
    def __init__(self):
        super(TAPTestRunner, self).__init__(stream=open(os.devnull, 'wb'))

def expectedFailure(note):
    """decorator to mark a test method as expected to fail (with a note)
    """
    def g(test_item):
        test_item.__taptest_expected_failure_note__ = note
        return unittest.expectedFailure(test_item)
    return g

@unittest.skip('skip example test cases')
class Test(unittest.TestCase):
    def test_example1_pass(self):
        pass
    def test_example2_fail(self):
        self.fail('dummy fail')
    def test_example3_err(self):
        raise RuntimeError('dummy')
    @unittest.skip('example skip')
    def test_example4_skip(self):
        pass
    @expectedFailure('expected failure note')
    def test_example5_expected_fail(self):
        self.fail('dummy fail')
    @expectedFailure('unexpected pass note')
    def test_example6_unexpected_pass(self):
        pass
