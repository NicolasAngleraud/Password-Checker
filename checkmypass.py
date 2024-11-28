import requests
import hashlib
import sys
import argparse


def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching {res.status_code}, check the API and try again.')
	return res


def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0
	
	
def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	head5char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(head5char)
	return get_password_leaks_count(response, tail)


def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f"'{password}' was found {count} times. It might be a good idea to change the password.")
		else:
			print(f"'{password}' was not found. The password seems safe.")


def get_parser_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("--file_path", help="Path of the file containing passwords to check.")
	parser.add_argument('-v', "--trace", action="store_true", help="Toggles the verbose mode. Default=False")
	args = parser.parse_args()
	return args


	
if __name__ == "__main__":

	args = get_parser_args()
	
	if '.txt' not in (path:= args.file_path):
		print("The file path is incorrect. It should be a .txt file containing one password to check per line.")
		sys.exit()
	
	try:
		with open(path, mode='r', encoding='utf-8') as f:
			passwords_to_check = [l.strip() for l in f.readlines()]
			main(passwords_to_check)
	except FileNotFoundError as err:
		print("The file path is incorrect.")
		raise err
	except:
		print("The file is incorrect. It should be a .txt file containing one password to check per line.")
	finally:
		sys.exit()
