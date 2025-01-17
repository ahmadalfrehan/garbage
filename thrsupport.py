from gevent.pywsgi import WSGIServer
from app import app  # Assuming your Flask app is named 'app'

if __name__ == "__main__":
    http_server = WSGIServer(("0.0.0.0", 5000), app)
    http_server.serve_forever()
