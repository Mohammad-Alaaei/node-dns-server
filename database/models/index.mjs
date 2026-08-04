import { DnsServer } from './dns-server.mjs';
import { DnsRule } from './dns-rule.mjs';
import { Record } from './record.mjs';
import { RecordValue } from './record-value.mjs';
import { Statistic } from './statistic.mjs';
import { Setting } from './setting.mjs';

/* -------------------------------------------------------------------------- */
/*                              Associations                                  */
/* -------------------------------------------------------------------------- */

DnsServer.hasMany(DnsRule, {
    foreignKey: 'server_id',
    as: 'rules',
    onDelete: 'CASCADE'
});
DnsRule.belongsTo(DnsServer, {
    foreignKey: 'server_id',
    as: 'server'
});

Record.hasMany(RecordValue, {
    foreignKey: 'record_id',
    as: 'values',
    onDelete: 'CASCADE'
});
RecordValue.belongsTo(Record, {
    foreignKey: 'record_id',
    as: 'record'
});

DnsServer.hasMany(RecordValue, {
    foreignKey: 'dns_server_id',
    as: 'recordValues',
    onDelete: 'CASCADE'
});
RecordValue.belongsTo(DnsServer, {
    foreignKey: 'dns_server_id',
    as: 'dnsServer'
});

/* -------------------------------------------------------------------------- */
/*                                  Exports                                   */
/* -------------------------------------------------------------------------- */

export {
    DnsServer,
    DnsRule,
    Record,
    RecordValue,
    Statistic,
    Setting
};

export default {
    DnsServer,
    DnsRule,
    Record,
    RecordValue,
    Statistic,
    Setting
};