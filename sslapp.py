# SSL certificate Checker

# adding the libraries used below
from flask import Flask, request, jsonify
import ssl
import socket
import datetime

app = Flask(__name__) # starting the flask instance

@app.route('/check', methods=['POST'])

def check_ssl_certificate():

    domain = request.json.get('domain') # retrieves the domain name from the JSON payload of the POST request.

    try:
        context = ssl.create_default_context() # create a default SSL/TLS context using the ssl module.

        with socket.create_connection((domain, 443)) as sock: # socket connection to the specified domain on port 443 (HTTPS).

            with context.wrap_socket(sock, server_hostname=domain) as sslsock: # wraps the socket connection with the SSL/TLS context, and the wrapped socket is stored in the sslsock variable.

                cert = sslsock.getpeercert() # we retrieve the SSL certificate of the domain from the wrapped socket.
                issuer = dict(x[0] for x in cert['issuer']) # extracting the issuer information from the SSL certificate and stores it in a dictionary.
                subject = dict(x[0] for x in cert['subject']) # extracts the subject information from the SSL certificate and stores it in a dictionary.
                valid_from = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z") #  converting the 'notBefore' field of the SSL certificate (which indicates the starting date of the certificate) into a datetime object.
                valid_to = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z") #  converting the 'notAfter' field of the SSL certificate (which indicates the expiration date) into a datetime object.
                now = datetime.datetime.now() # here we get the current date and time

                # Calculate number of days until expiry
                days_until_expiry = (valid_to - now).days

                return jsonify({ # returning the Json response containing the fileds needed as per the ones above
                    'domain': subject.get('commonName'),
                    'sslCertificate': issuer.get('organizationName'),
                    'validFrom': valid_from.strftime("%Y-%m-%d"),
                    'validTo': valid_to.strftime("%Y-%m-%d"),
                    'daysUntilExpiry': days_until_expiry,
                    'status': 'Valid' if valid_to > now else 'Expired',
                })
            
    except Exception as e: # here we catch any exceptions that may occur during the SSL certificate check process.
        return jsonify({'error': str(e)}), 500  # If an exception does occur, we return a JSON response containing the error message and a status code of 500 (Internal Server Error).

if __name__ == '__main__':
    app.run(debug=True) # running the flask application in debug mode
