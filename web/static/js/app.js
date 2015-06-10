import {Socket} from "phoenix"

let messagesContainer = $("#messages")
let imc	= $("#imc")
let ipc	= $("#ipc")
let cpc	= $("#cpc")
let dpc	= $("#dpc")
let ims	= $("#ims")
let ips	= $("#ips")
let cps	= $("#cps")
let dps	= $("#dps")
let cachehit = $("#cachehit")
let ssldispatch = $("#ssldispatch")

let socket = new Socket("/ws")
socket.connect()
let chan = socket.chan("rooms:lobby", {})
chan.join().receive("ok", chan => {
  console.log("Connection Established...")
})

chan.on("new_msg", payload => {
	messagesContainer.append(`<br/>[${Date()}] ${payload.body}`)
})
chan.on("db_msg", payload => {
	imc.text(`${payload.imc}`)
	ipc.text(`${payload.ipc}`)
	cpc.text(`${payload.cpc}`)
	dpc.text(`${payload.dpc}`)
	ims.text(`${payload.ims}`)
	ips.text(`${payload.ips}`)
	cps.text(`${payload.cps}`)
	dps.text(`${payload.dps}`)
	cachehit.text(`${payload.cachehit}`)
	ssldispatch.text(`${payload.ssldispatch}`)
})
