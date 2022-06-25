import os
import sys

from flask import Flask
from flask import render_template, redirect, url_for


app = Flask(__name__)
ip_file_path = sys.argv[1]
items_per_page = 50


ip_list = []
with open(ip_file_path, 'r') as f:
    for line in f:
        if line:
            ip_list.append(line.strip())


@app.route('/')
def index():
    return redirect(url_for('get_page', page_num=0))


@app.route('/<int:page_num>')
def get_page(page_num=0):
    context = {}
    context['title'] = os.path.basename(ip_file_path)

    page_count = len(ip_list) // items_per_page + 1 if len(ip_list) % items_per_page else len(ip_list) // items_per_page
    context['page_count'] = page_count
    if page_num < 0 or page_num >= page_count:
        context['page_num'] = 0
    context['page_num'] = page_num

    context['ip_list'] = ip_list[page_num * items_per_page : (page_num + 1) * items_per_page]

    return render_template('index.html', context=context)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)