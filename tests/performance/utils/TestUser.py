from create_user import create_user
from delete_user import delete_user
from launch_challenge import launch_challenge
from stop_challenge import stop_challenge

class TestUser:
    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email
        self.session = None

    def create(self):
        self.session = create_user(self.username, self.email, self.password)

        if not self.session:
            raise Exception("Failed to create user session.")

    def delete(self):
        if not self.session:
            raise Exception("User session not initialized. Cannot delete user.")

        delete_user(self.username, self.password)

    def launch_challenge(self, challenge_id, prints=False):
        launch_challenge(self.session, challenge_id, prints=prints)

    def stop_challenge(self, challenge_id, prints=False):
        stop_challenge(self.session, challenge_id, prints=prints)
