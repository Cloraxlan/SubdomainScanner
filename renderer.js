// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.
const {
    remote
} = require('electron');
var run = true;
const open = require('open');
const https = require('https');
const request = require('request');

const domainPing = require("domain-ping");
var currentdate = new Date();
var datetime = "Last Sync: " + currentdate.getDate() + "/" +
    (currentdate.getMonth() + 1) + "/" +
    currentdate.getFullYear() + " @ " +
    currentdate.getHours() + ":" +
    currentdate.getMinutes() + ":" +
    currentdate.getSeconds();

function sleep(ms) {
    return new Promise(resolve => {
        setTimeout(resolve, ms)
    })
}
subs = []
ips = []
obj = []
sub = {
    domain: "",
    status: "",
    time: "",
    ip: "",
    responce: ""
}
var txtbox = document.getElementById("url");
txtbox.addEventListener("keydown", function (e) {
    if (e.keyCode === 13) {  //checks whether the pressed key is "Enter"
        document.getElementById("get").click()
    }
});
get = (dom) => {

    var vt = require("node-virustotal");
    var con = vt.MakePublicConnection();
    con.setKey("8361d8d3d5c64f8530ca2d3baa7bc02e581d17217a384fdd7025e6ef0dff802a");
    console.log(con.getKey());
    con.setDelay(15000);
    console.log(con.getDelay());
    con.getDomainReport(dom, function (data) {
        subs = data.subdomains

        ips = []
        ip()

    }, function (err) {
        console.error(err);
    });

}
const shell = require('electron').shell;

function openURL(url) {

    event.preventDefault();
    shell.openExternal(url);

}
var green = function(cell, formatterParams){
    for(i =15;i <= $(".tabulator-cell").length;i++){
        if(i%15 ==0){
        console.log(i)
        $(".tabulator-cell")[i-1].innerHTML = `<button onclick="openURL('`+$(".tabulator-cell")[i-1].title+`')">Results</button>`
    }
    }

  
};
function render() {
    if (run) {
        var Tabulator = require('tabulator-tables');
        var table = new Tabulator("#example-table", {
            data: obj, //load row data from array
            layout: "fitColumns", //fit columns to width of table
            responsiveLayout: "hide", //hide columns that dont fit on the table
            tooltips: true, //show tool tips on cells
            addRowPos: "top", //when adding a new row, add it to the top of the table
            history: true, //allow undo and redo actions on the table
            pagination: "local", //paginate the data
            paginationSize: 20, //allow 7 rows per page of data
            movableColumns: true, //allow column order to be changed
            resizableRows: true, //allow row order to be changed

            initialSort: [ //set the initial sort order of the data
                {
                    column: "id",
                    dir: "asc"
                },
            ],
            columns: [ //Define Table Columns
                {
                    title: "Serial No.",
                    field: "id",
                },
                {
                    title: "Domain",
                    field: "domain",
                    cellClick: function (e, cell) {
                        openURL("http://" + cell._cell.value)
                    }
                },
                {
                    title: "IP",
                    field: "ip",
                },
                {
                    title: "Code",
                    field: "responce"
                },
                {
                    title: "Status",
                    field: "status",
                    formatter: "tickCross",
                    sorter: "boolean"
                },
                {
                    title: "Grade",
                    field: "grade",

                },
                {
                    title: "CSP",
                    field: "csp",
                    formatter: "tickCross",
                    sorter: "boolean"
                },
                {
                    title: "CORS",
                    field: "cors",
                    formatter: "tickCross",
                    sorter: "boolean"
                },
                {
                    title: "HSTS",
                    field: "hsts",
                    formatter: "tickCross",
                    sorter: "boolean"
                },
                {
                    title: "Redir",
                    field: "redir",
                    formatter: "tickCross",
                    sorter: "boolean"
                },
                {
                    title: "Cookie",
                    field: "cookie",
                    formatter: "tickCross",
                    sorter: "boolean"
                },
                {
                    title: "XSS",
                    field: "xss",
                    formatter: "tickCross",
                    sorter: "boolean"
                },
                {
                    title: "Server",
                    field: "server"
                },
                {
                    title: "Connection",
                    field: "connection"
                },
                {
                    title: "Results",
                    field: "results",
                    formatter:green,
                    cellClick: function (e, cell) {
                        openURL(cell._cell.value)
                    }
                },
            ]
        });
    }
   green()
}
function exportCSV(){
    table.download('csv', 'subdom.csv');
}
function ping(i) {
    domainPing(subs[i]) // Insert the domain you want to ping
        .then((res) => {
            obj[i].ip = res.ip
            obj[i].responce = res.statusCode
            obj[i].status = res.online

            //render()
        })
    if (i == obj.length - 1) {
        render()
        observe()
        setTimeout(handleObs, 5000)
        setTimeout(render, 5000)
        setTimeout(render, 7000)



    }
}

function handleObs() {
    for (var o = 0; o < obj.length; o++) {
        observe(o)
    }
}

function observe(o) {
    console.log(o)

    request.post("https://http-observatory.security.mozilla.org//api/v1/analyze?host=" + subs[o], {
        json: {
            rescan: true
        }
    }, (error, res, body) => {
        if (error) {
            console.error(error)

        }
        console.log((body).response_headers.Connection)
        obj[o].grade = (body).grade
        obj[o].server = (body).response_headers.Server
        obj[o].connection = (body).response_headers.Connection
        if((body).response_headers.Connection == null || (body).response_headers.Connection == undefined){
            obj[o].connection = "-"
        }

        results(o, (body).scan_id)
    })

}

function results(p, id) {
    request('https://http-observatory.security.mozilla.org//api/v1/getScanResults?scan='+id, {
        json: true
    }, (err, res, body) => {
        if (err) {
            return console.log(err);
        }
        console.log(res);
        obj[p].csp = body['content-security-policy'].pass
        obj[p].cors = body['cross-origin-resource-sharing'].pass
        obj[p].hsts = body['strict-transport-security'].pass
        obj[p].redir = body['redirection'].pass
        obj[p].cookie = body['cookies'].pass
        obj[p].xss = body['x-xss-protection'].pass
    });
}

function ip() {
    for (var i = 0; i < subs.length; i++) {
        var x = {
            domain: "",
            status: "",
            time: "",
            ip: "",
            responce: "",
            grade: "",
            csp: "",
            cors: "",
            hsts: "",
            redir: "",
            refer: "",
            xss: "",
            connection: "",
            server: "",
            cookie: ""            

        }
        x.domain = subs[i]
        x.results = "https://observatory.mozilla.org/analyze/"+subs[i]
        x.id = i + 1
        obj.push(x)
    }


    for (var i = 0; i < obj.length; i++) {
        ping(i)

    }
}