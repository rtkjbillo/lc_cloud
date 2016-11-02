
function pad2( s )
{
    return ('0' + s).slice(-2);
}

function pad3( s )
{
    return ('00' + s).slice(-3);
}

function ts_to_time( ts )
{
    // Create a new JavaScript Date object based on the timestamp
    // multiplied by 1000 so that the argument is in milliseconds, not seconds.
    var date = new Date(ts);
    return date.getUTCFullYear() + "-" + pad2(date.getUTCMonth()+1) + "-" + pad2(date.getUTCDate()) + " " + pad2(date.getUTCHours()) + ":" + pad2(date.getUTCMinutes()) + ":" + pad2(date.getUTCSeconds()) + "." + pad3(date.getUTCMilliseconds());
}

function pad(num, size){ return ('000000000' + num).substr(-size); }

function display_c(){
    var refresh=1000; // Refresh rate in milli seconds
    mytime=setTimeout('display_ct()',refresh)
}

function display_ct()
{
    var strcount
    var x = new Date()
    var x1 = x.getUTCFullYear() + "-" + pad( x.getUTCMonth() + 1, 2 ) + "-" + pad( x.getUTCDate(), 2 );
    x1 = x1 + " " +  pad( x.getUTCHours(), 2 ) + ":" +  pad( x.getUTCMinutes(), 2 ) + ":" +  pad( x.getUTCSeconds(), 2 );
    if( document.getElementById('utc_clock') ){
        document.getElementById('utc_clock').innerHTML = x1;
        tt=display_c();
    }
}

$( document ).ready(function() {
    $(".table-sorted").tablesorter( { sortList: [[0,0]] } );
    $(".table-sorted-asc").tablesorter( { sortList: [[0,0]] } );
    $(".table-sorted-desc").tablesorter( { sortList: [[0,1]] } );
    display_ct();
    $(".datetimepicker").datetimepicker( { pick12HourFormat: false, sideBySide: true, format: 'YYYY-MM-DD HH:mm:ss', useSeconds: true } );
});