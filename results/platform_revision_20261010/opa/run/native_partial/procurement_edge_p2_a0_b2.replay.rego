package audit.residual
import rego.v1
default allowed := false
allowed if {
0 = input.record.profile
__local5__2 = {__local3__2: __local4__2 | __local3__2 = input.record.base[__local4__2]}
every __local6__2, __local7__2 in [0, 1, 2, 3] { __local30__2 = input.record.base; __local7__2 in __local30__2}
every __local8__2, __local9__2 in [] { __local31__2 = input.record.base; not __local9__2 in __local31__2}
every __local10__2, __local11__2 in [[0, 1], [1, 2], [2, 3]] { data.audit.predicates.edge_allowed(input.record, __local5__2, __local11__2) }
}
allowed if {
1 = input.record.profile
__local5__2 = {__local3__2: __local4__2 | __local3__2 = input.record.base[__local4__2]}
every __local6__2, __local7__2 in [0, 1, 2, 3] { __local30__2 = input.record.base; __local7__2 in __local30__2}
every __local8__2, __local9__2 in [] { __local31__2 = input.record.base; not __local9__2 in __local31__2}
every __local10__2, __local11__2 in [[0, 1], [0, 2], [1, 3], [2, 3]] { data.audit.predicates.edge_allowed(input.record, __local5__2, __local11__2) }
}
allowed if {
2 = input.record.profile
__local5__2 = {__local3__2: __local4__2 | __local3__2 = input.record.base[__local4__2]}
every __local6__2, __local7__2 in [0, 2, 3] { __local30__2 = input.record.base; __local7__2 in __local30__2}
every __local8__2, __local9__2 in [] { __local31__2 = input.record.base; not __local9__2 in __local31__2}
every __local10__2, __local11__2 in [[2, 3]] { data.audit.predicates.edge_allowed(input.record, __local5__2, __local11__2) }
}
allowed if {
3 = input.record.profile
__local5__2 = {__local3__2: __local4__2 | __local3__2 = input.record.base[__local4__2]}
every __local6__2, __local7__2 in [0, 1] { __local30__2 = input.record.base; __local7__2 in __local30__2}
every __local8__2, __local9__2 in [] { __local31__2 = input.record.base; not __local9__2 in __local31__2}
every __local10__2, __local11__2 in [[0, 1]] { data.audit.predicates.edge_allowed(input.record, __local5__2, __local11__2) }
}
checks := [result | some request in input.requests; result := data.audit.residual.allowed with input as request]
