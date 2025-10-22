import threading
import time
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))

from TestUser import TestUser


class SingleUserSignupThread(threading.Thread):
    def __init__(self, user):
        threading.Thread.__init__(self)
        self.user = user
        self.success = False
        self.error = None

    def run(self):
        try:
            self.user.create()
            self.success = True
        except Exception as e:
            self.error = f"Error creating user {self.user.username}: {e}"


class SingleUserDeleteThread(threading.Thread):
    def __init__(self, user):
        threading.Thread.__init__(self)
        self.user = user
        self.success = False
        self.error = None

    def run(self):
        try:
            self.user.delete()
            self.success = True
        except Exception as e:
            self.error = f"Error deleting user {self.user.username}: {e}"


def parallel_user_signup_test(num_users, duration_seconds=10):
    create_threads = []

    for i in range(num_users):
        username = f"testuser_{i + 1}"
        password = "testpass"
        email = f"test{i + 1}@test.test"

        test_user = TestUser(username, password, email)
        thread = SingleUserSignupThread(test_user)
        create_threads.append(thread)


    create_timer_start = time.time()
    for thread in create_threads:
        thread.start()

    for thread in create_threads:
        thread.join()
    create_timer_end = time.time()
    create_duration = create_timer_end - create_timer_start

    create_thread_count = len(create_threads)
    create_success_count = 0
    create_failure_count = 0
    for thread in create_threads:
        if thread.success:
            create_success_count += 1
        else:
            create_failure_count += 1

    time.sleep(duration_seconds)

    delete_threads = []
    for thread in create_threads:
        if thread.success:
            delete_thread = SingleUserDeleteThread(thread.user)
            delete_threads.append(delete_thread)

    delete_timer_start = time.time()
    for thread in delete_threads:
        thread.start()

    for thread in delete_threads:
        thread.join()
    delete_timer_end = time.time()
    delete_duration = delete_timer_end - delete_timer_start

    delete_thread_count = len(delete_threads)
    delete_success_count = 0
    delete_failure_count = 0
    for thread in delete_threads:
        if thread.success:
            delete_success_count += 1
        else:
            delete_failure_count += 1


    create_errors = [thread.error for thread in create_threads if thread.error]
    delete_errors = [thread.error for thread in delete_threads if thread.error]

    results = {
        "create_thread_count": create_thread_count,
        "create_success_count": create_success_count,
        "create_failure_count": create_failure_count,
        "create_duration": create_duration,
        "create_errors": create_errors,
        "delete_thread_count": delete_thread_count,
        "delete_success_count": delete_success_count,
        "delete_failure_count": delete_failure_count,
        "delete_duration": delete_duration,
        "delete_errors": delete_errors
    }

    return results


if __name__ == "__main__":
    num_users = 1
    duration_seconds = 0

    results = parallel_user_signup_test(num_users, duration_seconds)

    print("User Signup Test Results:")
    print(f"Total Users Attempted: {results['create_thread_count']}")
    print(f"Successful Signups: {results['create_success_count']}")
    print(f"Failed Signups: {results['create_failure_count']}")
    print(f"Signup Duration (seconds): {results['create_duration']:.2f}")
    if results['create_errors']:
        print("Signup Errors:")
        for error in results['create_errors']:
            print(f"- {error}")

    print(f"\nTotal Users Attempted Deletion: {results['delete_thread_count']}")
    print(f"Successful Deletions: {results['delete_success_count']}")
    print(f"Failed Deletions: {results['delete_failure_count']}")
    print(f"Deletion Duration (seconds): {results['delete_duration']:.2f}")
    if results['delete_errors']:
        print("Deletion Errors:")
        for error in results['delete_errors']:
            print(f"- {error}")
