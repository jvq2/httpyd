print('WOOOOOOOOOOOOOOOOOOOO')
print('CACHOOOOOOOOOOOOOOOOOOOO')
print('path:', s.path)

s.send_response(200)
s.send_header("Content-type", "text/html;charset=utf-8")
s.end_headers()
s.wfile.write(bytes('<h2>Generated Page!</h2>','utf8'))
s.wfile.write(bytes('<div>Path: %s</div>'%(s.path,),'utf8'))
s.wfile.write(bytes('<br />','utf8'))