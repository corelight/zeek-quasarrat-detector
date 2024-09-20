module QuasarRAT;

export {
	## The notice when QuasarRAT C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed, };
}

event ssl_established(c: connection)
	{
	if ( ! c?$ssl )
		return;

	if ( c$ssl?$subject && c$ssl$subject == "CN=Quasar Server CA" )
		NOTICE([ $note=QuasarRAT::C2_Traffic_Observed, $msg="Potential QuasarRAT C2 discovered via a default SSL certificate.", $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
	}
