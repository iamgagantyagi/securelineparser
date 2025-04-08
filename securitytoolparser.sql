CREATE TABLE public.builds (
    id                   bigserial     NOT NULL,
    build_number         varchar       NULL,
    module               varchar       NULL,
    app                  varchar       NULL,
    tool                 varchar       NULL,
    branch               varchar       NULL,
    is_latest            bool          DEFAULT false NULL,
    inserted_at          timestamptz   DEFAULT CURRENT_TIMESTAMP NULL,
    updated_at           timestamptz   DEFAULT CURRENT_TIMESTAMP NULL,
    build_status         varchar       NULL,
    run_remarks          varchar       NULL,
    status_details       json          NULL,
    tool_build_starttime timetz        NULL,
    tool_build_endtime   timetz        NULL,
    CONSTRAINT builds_pk PRIMARY KEY (id)
);

CREATE TABLE public.findings (
    id                   bigserial     NOT NULL,
    build_id             int8          NULL,
    date                 timestamptz   DEFAULT CURRENT_TIMESTAMP NULL,
    "cwe-cve"              varchar       NULL,
    toolname             varchar       NULL,
    severity             varchar       NULL,
    title                text          NULL,
    description          text          NULL,
    remediation          text          NULL,
    systeminfo           varchar       NULL,
    component            varchar       NULL,
    project              varchar       NULL,
    type                 varchar       NULL,
    securitycategory     varchar       NULL,
    line                 varchar       NULL,
    status               varchar       NULL,
    filepath             text          NULL,
    key                  varchar       NULL,
    name                 text          NULL,
    rule                 text          NULL,
    trace                varchar       NULL,
    kind                 varchar       NULL,
    namespace            varchar       NULL,
    cis_control          varchar       NULL,
    comments             text          NULL,
    is_new               bool          NULL,
    suppressed           bool          NULL,
    unique_key           varchar       NOT NULL,
    CONSTRAINT findings_pk PRIMARY KEY (id),
    CONSTRAINT findings_fk FOREIGN KEY (build_id) REFERENCES public.builds(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE public.cis_controls_mappings (
	id bigserial NOT NULL,
	cis_control varchar NOT NULL,
    title varchar NOT NULL,
	severity varchar NOT NULL,
	CONSTRAINT cis_controls_mappings_pk PRIMARY KEY (id),
	CONSTRAINT cis_controls_mappings_unique UNIQUE (cis_control)
);