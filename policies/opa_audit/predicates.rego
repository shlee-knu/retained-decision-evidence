package audit.predicates

import rego.v1

# Independent encoding of the declared four-profile procurement grammar.
# Records are COMPLETE normalized states. Missing fields are never a value in
# this interface; the Python adapter enumerates every supported completion.
procurement_allowed(record, catalog) if {
    rule := catalog[record.profile]
    positions := {activity: index | some index, activity in record.base}
    every activity in rule.required {
        activity in record.base
    }
    every activity in rule.forbidden {
        not activity in record.base
    }
    every edge in rule.edges {
        edge_allowed(record, positions, edge)
    }
}

edge_allowed(record, _, edge) if {
    not edge[1] in record.base
}

edge_allowed(record, positions, edge) if {
    edge[1] in record.base
    edge[0] in record.base
    positions[edge[0]] < positions[edge[1]]
    record.ranks[positions[edge[0]]] <= record.ranks[positions[edge[1]]]
}

procurement_label(record, catalog) := true if {
    procurement_allowed(record, catalog)
} else := false

labels := [[procurement_label(record, input.old_catalog),
            procurement_label(record, input.new_catalog)] |
    some record in input.records
]

old_allowed if {
    procurement_allowed(input.record, input.old_catalog)
}

new_allowed if {
    procurement_allowed(input.record, input.new_catalog)
}

default old_decision := false
old_decision if old_allowed

default new_decision := false
new_decision if new_allowed

# The logged fixture uses catalog data pinned INSIDE its revisioned bundle.
# The matrix evaluator above deliberately receives explicit catalog arguments.
default logged_old_decision := false
logged_old_decision if {
    procurement_allowed(input.record, data.catalogs.baseline)
}
