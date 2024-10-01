module QuasarRAT;

@load ja3

export {
	## The notice when QuasarRAT C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed, };
}

event ssl_established(c: connection)
	{
	if ( ! c?$ssl )
		return;

	if ( (c$ssl?$subject && c$ssl$subject == "CN=Quasar Server CA") || (c$ssl?$ja3 && !c$ssl?$server_name && c$ssl$ja3 == "c12f54a3f91dc7bafd92cb59fe009a35" ) )
		NOTICE([ $note=QuasarRAT::C2_Traffic_Observed, $msg="Potential QuasarRAT C2 discovered via a default SSL certificate.", $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
	}
