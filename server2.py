#!/usr/bin/python

from flask import Flask, jsonify, redirect, render_template
import math, json
import phatsniffer

app = Flask(__name__)

@app.route('/')
def index():
	data = phatsniffer.get_sniffer_data()
	data_beacons = data['beacons']
	data_clients = data['clients']
	beacons = sorted(data_beacons.iteritems(), key=lambda x: -x[1]['rssi'])
	clients = sorted(data_clients.iteritems(), key=lambda x: -x[1]['rssi'])
	beacon_clients = {}
	for beacon in data_beacons:
		beacon_clients[beacon] = []
	for client in data_clients:
		beacon = data_clients[client]['beacon']
		if beacon in data_beacons:
			if beacon not in beacon_clients:
				beacon_clients[beacon] = []
			beacon_clients[beacon].append(client)
	circles = {}
	circles['name'] = 'root'
	circles['children'] = []
	circles_beacons = circles['children']
	for beacon in beacon_clients:
		data_beacon = data_beacons[beacon]
		circles_beacon = {}
		if 'vendor' in data_beacon:
			circles_beacon['name'] = data_beacon['vendor']
		else:
			circles_beacon['name'] = 'Unknown'
		if len(beacon_clients[beacon]) == 0:
			if data_beacon['rssi'] > -99:
				circles_beacon['size'] = 2* (math.sqrt(100+data_beacon['rssi']))
			else:
				circles_beacon['size'] = 1
		else:
			circles_beacon['children'] = []
			circles_clients = circles_beacon['children']
			for client in beacon_clients[beacon]:
				data_client = data_clients[client]
				circles_client = {}
				if 'vendor' in data_client:
					circles_client['name'] = data_client['vendor']
				else:
					circles_client['name'] = 'Unknown'
				if data_client['rssi'] > -99:
					circles_client['size'] = 2 * (math.sqrt(100+data_client['rssi']))
				else:
					data_client['size'] = 1
				circles_clients.append(circles_client)
		circles_beacons.append(circles_beacon)
		
	return render_template('/flare.html', beacons=beacons, clients=clients, circles=json.dumps(circles), circles2=json.dumps(circles))

@app.route('/download')
def download():
	return jsonify(phatsniffer.get_sniffer_data())

@app.route('/reset')
def reset():
	phatsniffer.reset_phat()
	return redirect('/')


if __name__ == '__main__':
	phatsniffer.read_vendors('data/vendors.tsv')
	app.run(debug=False, host='127.0.0.1')
