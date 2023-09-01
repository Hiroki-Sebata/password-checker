import requests
import hashlib
import sys
'''
url = 'https://api.pwnedpasswords.com/range/'+ 'CBFDA' #it's SHA1 Hash Generator's first 5 digits
res = requests.get(url)

print(res) #returned 400 and it means it doesn't work 200 should be the correct one

print(res) #returned 200 it means the password information is secured. 
'''

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/'+ query_char 
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h,count in hashes:
        if h==hash_to_check:
            return count
    return 0
            

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() 
    #what they are doing is first .sha1 to encrypt the "password" and use 'UTF-8' to encode then use hexadecimal deigits (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F. A, B, C, D, E, F) conversion then make the alphabets upper letters
    first5_char,last5_char = sha1password[:5],sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response,last5_char)

def main(argv):
    for password in argv:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... You should change your password')
        else:
            print(f'{password} was not found. It\'s secured')

#if __name__ == '__main__':

sys.exit(main(sys.argv[1:]))