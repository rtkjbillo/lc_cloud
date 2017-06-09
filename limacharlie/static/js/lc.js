function copyToClipboard(element) {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val($(element).text()).select();
    document.execCommand("copy");
    $temp.remove();
}

function pad2( s )
{
    return ('0' + s).slice(-2);
}

function pad3( s )
{
    return ('00' + s).slice(-3);
}

function pad(num, size){ return ('000000000' + num).substr(-size); }

function display_ct()
{
    var strcount;
    var x = new Date();
    var x1 = x.getUTCFullYear() + "-" + pad( x.getUTCMonth() + 1, 2 ) + "-" + pad( x.getUTCDate(), 2 );
    x1 = x1 + " " +  pad( x.getUTCHours(), 2 ) + ":" +  pad( x.getUTCMinutes(), 2 ) + ":" +  pad( x.getUTCSeconds(), 2 );
    if( document.getElementById('utc_clock') ){
        document.getElementById('utc_clock').innerHTML = x1;
        tt=display_c();
    }
}

function display_c(){
    var refresh=1000; // Refresh rate in milli seconds
    mytime=setTimeout('display_ct()',refresh);
}

function ts_to_time( ts )
{
    // Create a new JavaScript Date object based on the timestamp
    // multiplied by 1000 so that the argument is in milliseconds, not seconds.
    var date = new Date(ts);
    return date.getUTCFullYear() + "-" + pad2(date.getUTCMonth()+1) + "-" + pad2(date.getUTCDate()) + " " + pad2(date.getUTCHours()) + ":" + pad2(date.getUTCMinutes()) + ":" + pad2(date.getUTCSeconds()) + "." + pad3(date.getUTCMilliseconds());
}

function do_refresh_online(thisIndicator, sid, rate){
	jQuery.getJSON( '/sensor_state',
        { sensor_id : sid } ).done(function(data) {
										if(data.live_status){ 
											$(thisIndicator).css('color', 'lawngreen');
											$(thisIndicator).text('thumb_up');
										}
										else 
										{
											$(thisIndicator).css('color', 'red');
											$(thisIndicator).text('thumb_down');
										}
										update_status(true); })
                           .fail(function(){
                           		$(thisIndicator).css('color', 'red'); 
                           		$(thisIndicator).text('thumb_down');
                           		update_status(false);
                           	})
                           .always(function(){setTimeout( function(){do_refresh_online(thisIndicator, sid, rate);}, rate * 1000 );});
}

function do_refresh_ip(thisIndicator, sid, rate){
	jQuery.getJSON( '/sensor_ips',
        { sensor_id : sid } ).done(function(data) {
        						$(thisIndicator).text( '' + data.external + ' / ' + data.internal ); 
        					})
                           .fail(function(){
                           		$(thisIndicator).text( 'N/A / N/A' );
                           	})
                           .always(function(){setTimeout( function(){do_refresh_ip(thisIndicator, sid, rate);}, rate * 1000 );});
}

function do_refresh_lastevents(thisIndicator, sid, rate){
	jQuery.getJSON( '/sensor_lastevents',
        { sensor_id : sid } ).done(function(data) {
        						$(thisIndicator).empty();
        						jQuery.each(data.events,function(){
        							var eName = this[ 0 ];
        							var eId = this[ 1 ];
        							$(thisIndicator).append(
        								$("<tr>").append(
        									$("<td>").append(
        										$("<b>").append(
        											$("<a>").attr('target', '_blank').text(eName.replace('notification.', '')).attr("href", "/event?eid=" + eId)
        										)
        									)
        								).addClass("mdl-data-table__cell--non-numeric")
        							);
        						});
        					})
                           .fail(function(){
                           		$(thisIndicator).empty();
                           	})
                           .always(function(){setTimeout( function(){do_refresh_lastevents(thisIndicator, sid, rate);}, rate * 1000 );});
}

function do_refresh_lastchanges(thisIndicator, sid, rate){
	jQuery.getJSON( '/hostchanges',
        { sensor_id : sid } ).done(function(data) {
        						$(thisIndicator).empty();
    						for( var eType in data.changes )
    							{
    								var changes = data.changes[ eType ];
    								for( var change in changes[ '+' ] )
    								{
    									var ts = ts_to_time( changes[ '+' ][ change ][ 1 ] );
    									var eId = changes[ '+' ][ change ][ 0 ];
    									$(thisIndicator).append( 
    										$("<tr>")
    										.append($("<td>").append(
	        												$("<i>").addClass("material-icons").text("add")
	        											).addClass("mdl-data-table__cell--non-numeric"))
    										.append( $("<td>").text( ts ).addClass("mdl-data-table__cell--non-numeric") )
    										.append( $("<td>").text( eType.replace( 'notification.', '' ) ).addClass("mdl-data-table__cell--non-numeric") )
    										.append( $("<td>").append(
	        												$("<a>").attr('target', '_blank').text(change).attr("href", "/event?eid=" + eId)
	        											).addClass("mdl-data-table__cell--non-numeric") )
    									);
    								}
    								for( var change in changes[ '-' ] )
    								{
    									var ts = ts_to_time( changes[ '-' ][ change ][ 1 ] );
    									var eId = changes[ '-' ][ change ][ 0 ];
    									$(thisIndicator).append( 
    										$("<tr>")
    										.append($("<td>").append(
	        												$("<i>").addClass("material-icons").text("remove")
	        											).addClass("mdl-data-table__cell--non-numeric"))
    										.append( $("<td>").text( ts ).addClass("mdl-data-table__cell--non-numeric") )
    										.append( $("<td>").text( eType.replace( 'notification.', '' ) ).addClass("mdl-data-table__cell--non-numeric") )
    										.append( $("<td>").append(
	        												$("<a>").attr('target', '_blank').text(change).attr("href", "/event?eid=" + eId)
	        											).addClass("mdl-data-table__cell--non-numeric") )
    									);
    								}
    							}
        					})
                           .fail(function(){
                           		$(thisIndicator).empty();
                           	})
                           .always(function(){setTimeout( function(){do_refresh_lastchanges(thisIndicator, sid, rate);}, rate * 1000 );});
}

function update_status(isLive){
	if(isLive){ 
		$(".update_status").css('color', 'lawngreen');
	}
	else 
	{
		$(".update_status").css('color', 'red');
	}
}

$(function() {
	lc_init_handlers();
	display_ct();
});

function lc_init_handlers() {
    $(".click-to-copy")
        .click( function(){ 
            copyToClipboard( $(this) );
            $(this).css('cursor', 'pointer')
                   .addClass( 'mdl-badge mdl-badge--overlap' )
                   .attr( 'data-badge', 'copied' );
            var that = this;
            setTimeout( function(){ $(that).removeClass( 'mdl-badge mdl-badge--overlap' ).removeAttr( 'data-badge' ); }, 5000 ); 
        } );

    $(".online_status").each( function() {
        var sid = $(this).attr('sid');
        var rate = Number($(this).attr('rate'));
        if( isNaN( rate ) )
        {
            rate = 5;
        }
        do_refresh_online(this, sid, rate);
    });

    $(".last_sensor_ip").each( function() {
        var sid = $(this).attr('sid');
        var rate = Number($(this).attr('rate'));
        if( isNaN( rate ) )
        {
            rate = 30;
        }
        do_refresh_ip(this, sid, rate);
    });

    $(".last_sensor_events").each( function() {
        var sid = $(this).attr('sid');
        var rate = Number($(this).attr('rate'));
        if( isNaN( rate ) )
        {
            rate = 10;
        }
        do_refresh_lastevents(this, sid, rate);
    });

    $(".last_sensor_changes").each( function() {
        var sid = $(this).attr('sid');
        var rate = Number($(this).attr('rate'));
        if( isNaN( rate ) )
        {
            rate = 30;
        }
        do_refresh_lastchanges(this, sid, rate);
    });
}

function msTsToTime( ts ) {
    var t = new Date( ts );
    return '' + t.getUTCFullYear() + '-' + pad( t.getUTCMonth() + 1, 2 ) + '-' + pad( t.getUTCDay(), 2 ) + ' ' + pad( t.getUTCHours(), 2 ) + ':' + pad( t.getUTCMinutes(), 2 ) + ':' + pad( t.getUTCSeconds(), 2 );
}