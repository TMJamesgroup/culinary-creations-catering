import os, unittest
os.environ["DATABASE_URL"]="postgresql://synthetic:synthetic@127.0.0.1:1/synthetic"
os.environ["ADMIN_TOKEN"]="synthetic-test-only-not-a-production-secret"
from backend.app import app
from fastapi.testclient import TestClient
class SecurityTests(unittest.TestCase):
    def test_response_policy_and_auth(self):
        with TestClient(app) as c:
            for path, status in [("/api/admin/inquiries", 401), ("/no-such-path",404)]:
                response=c.get(path)
                self.assertEqual(response.status_code,status)
                self.assertEqual(response.headers.get("cache-control"),"no-store")
            response=c.options("/api/inquiries",headers={"Origin":"https://culinary-creations-catering.onrender.com","Access-Control-Request-Method":"POST"})
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.headers.get("cache-control"),"no-store")
if __name__=="__main__": unittest.main()
