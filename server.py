#flask server

from flask import Flask,request,jsonify

from db_orm import get_requests

#serialize
app = Flask(__name__,static_folder='html',
        static_url_path='')

@app.route('/api/')
def api():
    args = request.args
    page = int(args['page'])
    pagesize = int(args['pagesize'])
    rets = get_requests(page*pagesize,pagesize)
    return jsonify({'Reqs':rets})
if __name__ == '__main__':
    app.run('0.0.0.0','8080')

