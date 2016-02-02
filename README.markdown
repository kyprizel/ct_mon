Description
===========

ct_mon monitors Certificate Trasparency logs by specified regexps in CN or SAN.

Configuration params
====================

match_subject_regex
-------------------

**default:**required param

**example:**"(?i)(yandex\\.|yandex-team)"

Regexp to search certificates

notify_persons
--------------

**default:**[]

**example:**["eldar@kyprizel.net"]

List of emails to notify about new certificates

mongo_uri
---------

**default:**required param

**example:**localhost

MongoDB connection parameters, will be used to store matched certificate entries and monitor state

store_matches
-------------

**default:**false

**example:**true

If true - store found certificates in DB

save_state
----------

**default:**30

**example:**600

Number of seconds after which  monitor state will be stored to DB

smtp_from
---------

**default:**empty

**example:**user@domain.com

SMTP From value

smtp_host
---------

**default:**empty

**example:**localhost

SMTP host

smtp_port
---------
**default:**25
**example:**25

SMTP port

smtp_subject
------------

**default:**"Certificate Transparency monitor notification"

**example:**"CT monitor notification"

Mail subject

notify_on_match
---------------

**default:**false

**example:**true

If true - persons listed in notify_persons will be notified on every matched certificate

ca_whitelist
------------

**default:**[]

**example:**[YandexExternalCA", "GlobalSign Organization Validation CA - G2", "Yandex CA"]

Whitelist of CAs, certificates signed by this CAs will pass the test

start_index
-----------

**default:**0

**example:**102780000

CT index to start fetching from, bigger value overrides DB state

rescan_period
-------------

**default:**0

**example:**30

Number of seconds to launch a rescan,
if not set - daemon will exit on reaching the end of log.

