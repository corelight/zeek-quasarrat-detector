module QuasarRAT;

@load packages/ja3

export {
	## The notices when QuasarRAT C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed_Cert, C2_Traffic_Observed_JA3 };
}

event ssl_established(c: connection)
	{
	if ( ! c?$ssl )
		return;

	if ( c$ssl?$subject && c$ssl$subject == "CN=Quasar Server CA" )
		NOTICE([ $note=QuasarRAT::C2_Traffic_Observed_Cert, $msg="Potential QuasarRAT C2 - default SSL certificate discovered.",
		    $conn=c, $identifier=cat(c$id$orig_h, c$id$resp_h) ]);

	if ( c$ssl?$ja3 && ! c$ssl?$server_name
	    && c$ssl$ja3 == "c12f54a3f91dc7bafd92cb59fe009a35" )
		NOTICE([ $note=QuasarRAT::C2_Traffic_Observed_JA3,
		    $msg="Potential QuasarRAT C2 - client JA3 discovered.",
		    $conn=c, $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
	}
