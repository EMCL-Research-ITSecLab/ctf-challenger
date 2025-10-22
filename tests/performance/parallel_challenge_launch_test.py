import threading
import time
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))

from TestUser import TestUser


class SingleChallengeLaunchThread(threading.Thread):
    def __init__(self, user, challenge_id, prints=False):
        threading.Thread.__init__(self)
        self.user = user
        self.challenge_id = challenge_id
        self.success = False
        self.error = None
        self.prints = prints

    def run(self):
        try:
            self.user.launch_challenge(self.challenge_id, prints=self.prints)
            self.success = True
        except Exception as e:
            self.error = f"Error for user {self.user.username}: {e}"


class SingleChallengeStopThread(threading.Thread):
    def __init__(self, user, challenge_id, prints=False):
        threading.Thread.__init__(self)
        self.user = user
        self.challenge_id = challenge_id
        self.success = False
        self.error = None
        self.prints = prints

    def run(self):
        try:
            self.user.stop_challenge(self.challenge_id)
            self.success = True
        except Exception as e:
            self.error = f"Error stopping challenge for user {self.user.username}: {e}"


def parallel_challenge_launch_test(challenge_id, num_parallel_instances, duration_seconds=60, prints=False):
    test_users = []

    for i in range(num_parallel_instances):
        username = f"testuser_{i + 1}"
        password = "testpass"
        email = f"test{i + 1}@test.test"

        test_user = TestUser(username, password, email)
        test_user.create()
        test_users.append(test_user)

    launch_threads = []
    for user in test_users:
        thread = SingleChallengeLaunchThread(user, challenge_id, prints=prints)
        launch_threads.append(thread)

    launch_timer_start = time.time()
    for thread in launch_threads:
        thread.start()

    for thread in launch_threads:
        thread.join()
    launch_timer_end = time.time()
    launch_duration = launch_timer_end - launch_timer_start

    launch_thread_count = len(launch_threads)
    launch_success_count = 0
    launch_failure_count = 0
    for thread in launch_threads:
        if thread.success:
            launch_success_count += 1
        else:
            launch_failure_count += 1

    time.sleep(duration_seconds)

    stop_threads = []
    for launch_thread in launch_threads:
        if launch_thread.success:
            stop_thread = SingleChallengeStopThread(launch_thread.user, challenge_id, prints=prints)
            stop_threads.append(stop_thread)

    stop_timer_start = time.time()
    for thread in stop_threads:
        thread.start()

    for thread in stop_threads:
        thread.join()
    stop_timer_end = time.time()
    stop_duration = stop_timer_end - stop_timer_start

    stop_thread_count = len(stop_threads)
    stop_success_count = 0
    stop_failure_count = 0
    for thread in stop_threads:
        if thread.success:
            stop_success_count += 1
        else:
            stop_failure_count += 1

    for user in test_users:
        user.delete()

    launch_errors = [thread.error for thread in launch_threads if thread.error]
    stop_errors = [thread.error for thread in stop_threads if thread.error]

    results = {
        "launch_success_count": launch_success_count,
        "launch_failure_count": launch_failure_count,
        "launch_thread_count": launch_thread_count,
        "launch_duration_seconds": launch_duration,
        "launch_errors": launch_errors,
        "stop_success_count": stop_success_count,
        "stop_failure_count": stop_failure_count,
        "stop_thread_count": stop_thread_count,
        "stop_duration_seconds": stop_duration,
        "stop_errors": stop_errors
    }

    return results


if __name__ == "__main__":
    challenge_id = 1
    num_parallel_instances = 10
    duration_seconds = 10

    results = parallel_challenge_launch_test(challenge_id, num_parallel_instances, duration_seconds, prints=True)

    print(f"Total Launch Attempts: {results['launch_thread_count']}")
    print(f"Successful Launches: {results['launch_success_count']}")
    print(f"Failed Launches: {results['launch_failure_count']}")
    print(f"Launch Duration (seconds): {results['launch_duration_seconds']:.2f}")
    if results['launch_errors']:
        print("Launch Errors:")
        for error in results['launch_errors']:
            print(f" - {error}")

    print(f"\nTotal Stop Attempts: {results['stop_thread_count']}")
    print(f"Successful Stops: {results['stop_success_count']}")
    print(f"Failed Stops: {results['stop_failure_count']}")
    print(f"Stop Duration (seconds): {results['stop_duration_seconds']:.2f}")
    if results['stop_errors']:
        print("Stop Errors:")
        for error in results['stop_errors']:
            print(f" - {error}")
