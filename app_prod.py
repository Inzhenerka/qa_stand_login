from src.flask_app import app
from waitress import serve
import logging

logger = logging.getLogger('waitress')
logger.setLevel(logging.INFO)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=80)
