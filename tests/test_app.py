import os,tempfile,unittest
import app as mod
class PhishGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True);self.old=mod.DB;mod.DB=os.path.join(self.tmp.name,'test.db');mod.init_db();mod.app.config['TESTING']=True;self.client=mod.app.test_client()
    def tearDown(self):mod.DB=self.old;self.tmp.cleanup()
    def token(self):
        with self.client.session_transaction() as s:return s['csrf']
    def login(self,user,password):
        self.client.get('/login');return self.client.post('/login',data={'username':user,'password':password,'csrf':self.token()},follow_redirects=True)
    def test_login_and_dashboard(self):
        r=self.login('employee','DemoEmployee!2026');self.assertIn(b'Security overview',r.data)
    def test_analyst_requires_role(self):
        self.login('employee','DemoEmployee!2026');self.assertEqual(self.client.get('/analyst').status_code,403)
    def test_report_submission(self):
        self.login('employee','DemoEmployee!2026');r=self.client.post('/report',data={'csrf':self.token(),'sender':'fake@example.test','subject':'Urgent','reason':'Unrecognized domain'},follow_redirects=True);self.assertIn(b'PH-0003',r.data)
    def test_csrf_enforced(self):
        self.login('employee','DemoEmployee!2026');self.assertEqual(self.client.post('/report',data={'sender':'x','subject':'y','reason':'z'}).status_code,400)
    def test_quiz_grading(self):
        self.login('employee','DemoEmployee!2026');self.client.get('/training')
        with self.client.session_transaction() as s: ids=list(s['quiz_ids'])
        d={'csrf':self.token()};d.update({'q'+str(i):mod.QUESTIONS[n][3] for i,n in enumerate(ids)});r=self.client.post('/training',data=d);self.assertIn(b'10 / 10 correct',r.data)
        self.client.get('/training')
        with self.client.session_transaction() as s: self.assertFalse(set(ids)&set(s['quiz_ids']))
    def test_analyst_review(self):
        self.login('analyst','DemoAnalyst!2026');r=self.client.post('/analyst/2',data={'csrf':self.token(),'status':'phishing','note':'Fictional demo'},follow_redirects=True);self.assertEqual(r.status_code,200)
if __name__=='__main__':unittest.main()
