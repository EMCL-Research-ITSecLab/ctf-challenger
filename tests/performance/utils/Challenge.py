from setup_challenge import setup_challenge
from delete_challenge import delete_challenge

class Challenge:
    def __init__(self, admin_session, path_to_yaml, prints=False):
        self.admin_session = admin_session
        self.path_to_yaml = path_to_yaml
        self.prints = prints
        self.challenge_id = None

    def setup(self, upload_ovas=True):
        self.challenge_id = setup_challenge(self.admin_session, self.path_to_yaml, upload_ovas=upload_ovas, prints=self.prints)
        return self.challenge_id

    def delete(self):
        if not self.challenge_id:
            raise Exception("Challenge ID not set. Cannot delete challenge.")

        delete_challenge(self.admin_session, self.challenge_id, prints=self.prints)
        self.challenge_id = None
