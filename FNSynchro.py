import os, commands, logging
from configobj import ConfigObj
from optparse import OptionParser

log = logging.getLogger("FNSynchro")
hdlr = logging.FileHandler('/var/log/FNSynchro/FNSynchro.log')
FORMAT='%(asctime)s\t%(levelname)s\t%(message)s'
formatter = logging.Formatter(FORMAT)
logging.basicConfig(format=FORMAT) # log sur console
hdlr.setFormatter(formatter)
log.addHandler(hdlr)
log.setLevel(logging.DEBUG) #set verbosity to show all messages of severity >= DEBUG

class initConfig:
    def parse_cli(self,argv):
        """ Commandline parser """
        parser = OptionParser(usage = '%prog [options]')
        # options
        parser.add_option('--config', type='string', dest='config', metavar='config',
               help='configuration, default=/etc/FNSynchro/FNSynchro.ini')

        parser.add_option('--object', type='string', dest='object', metavar='object',
               help='sync object, default=all')

        (opts, _) = parser.parse_args(argv)

        return opts

    def parse_ini(self, cfg_file='/etc/FNSynchro/FNSynchro.ini', object='all'):
        """
        This is the configuration parser, it parses /etc/FNSynchro/FNSynchro.ini or any other file passed to the cli.
        accepts
            cfg_file: file path of the INI file
        returns
            dict(foo): describing the backup objects 
        """
        config = ConfigObj(cfg_file)
        if object not in [ None, '', 'all']:
            sections = ['general', object]
        else:
            sections = config.sections
        foo = {}
        for section in sections:
            bar = config[section]
            if section == 'general':
                general = {}
                for def_key in bar.iterkeys():
                    general[def_key] = bar.get(def_key)
            else:
                foo[section] = {}
                foo[section]['pattern'] = []
                foo[section]['exceptions'] = []
                foo[section]['excludes'] = []
                for pattern_item in bar.get('pattern').split('/'):
                    if pattern_item.startswith('__'):
                        if not bar.get(pattern_item[2:]):
                            foo[section]['pattern'].append(general[pattern_item[2:]])
                        else:
                            foo[section]['pattern'].append(bar.get(pattern_item[2:]))
                    elif pattern_item.startswith(':'):
                        for exception in bar.get(pattern_item[1:])['exceptions']:
                            foo[section]['exceptions'].append(os.path.join(pattern_item[1:],exception))
                    else:
                        foo[section]['pattern'].append([pattern_item])
                if bar.get('excludes'):
                    for exclude_item in bar.get('excludes'):
                        if exclude_item.startswith('__'):
                            foo[section]['excludes'].append(bar.get(exclude_item[2:]))
                        else:
                            foo[section]['excludes'].append(exclude_item)
                    if general['excludes']:
                        foo[section]['excludes'].append(general['excludes'])
                else:
                    foo[section]['excludes'].extend(general['excludes'])
                src = ''
                if bar.get('src'):
                    src_val = bar.get('src')
                else:
                    src_val = general['src']
                for src_item in src_val.split('/'):
                    if src_item.startswith('__'):
                        if not bar.get(src_item[2:]):
                            src = os.path.join(src,general[src_item[2:]])
                        else:
                            src = os.path.join(src,bar.get(src_item[2:]))
                    else:
                        src = os.path.join(src,src_item)
                foo[section]['src'] = src
                dst = ''
                if bar.get('dst'):
                    dst_val = bar.get('dst')
                else:
                    dst_val = general['dst']
                for dst_item in dst_val.split('/'):
                    if dst_item.startswith('__'):
                        if not bar.get(dst_item[2:]):
                            dst = os.path.join(dst,general[dst_item[2:]])
                        else:
                            dst = os.path.join(dst,bar.get(dst_item[2:]))
                        #foo[section]['dst'].append(bar.get(dst_item[2:]))
                    else:
                        #foo[section]['dst'].append(dst_item)
                        dst = os.path.join(dst_item,dst)
                foo[section]['dst'] = dst
        return foo

    def get_config(self, argv=None):
        options = self.parse_cli(argv)
        return self.parse_ini(options.config, options.object)

#rsyn wrapper
def rsync(src,dst,filters=[]):
    """ 
    Wrapoper around rsync program
    accepts
        str(src): rsync source
        str(dst): rsync destination
        str(filters): a long string of filters to apply to the rsync cli (refer to the rsync man pages for --filter and "FILTER RULES")
    returns
        Bool
    """
    count = 0
    cmd = "rsync -e ssh -rLptn --delete --delete-after --inplace %s %s %s" % (filters, src, dst)
    log.info(cmd)
    status = -1
    while status not in [None, 0] and count < 3:
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            log.error(output)
            count = count+1
        else:
            return True
    return False

    
#generate the filters
def filter_gen(npattern,ipath=[],filter=''):
    """
    Takes a pattern as defined in the cfg file and creates a set of "--filter=" arguments to be passed to the rsyn command later
    accepts
        npattern: a list of lists of the path defined
        e.g. [['fremantle', 'harmattan'], ['pool', 'dists'], ['default'], ['current', 'pre-release', 'previous']]
        str(filter): a filter to be added to the filters generated, when passed it preceeds the filters generated by this function
    returns
        str(filters): a string of "--filter=" arguments
    """
    if len(npattern) < 1:
        return filter
    if len(ipath) == 0:
        ipath = ['']
    sub_list = npattern.pop(0)
    tmp_ipath = []
    for old_path in ipath:
        for item in sub_list:
            path = os.path.join(old_path,item)
            filter = filter + "--filter='+ %s' "%path
            tmp_ipath.append(path)
    for dir in tmp_ipath:
        filter = filter + "--filter='- %s/*' " %os.path.dirname(dir)
    return filter_gen(npattern,tmp_ipath,filter)

def sync(config):
    npattern = config['pattern']
    filters = filter_gen(npattern)
    if config['excludes']:
        for exclude in config['excludes']:
            filters = filters + "--exclude='%s' " %exclude
    if len(config['exceptions']) > 0:
        for exception in config['exceptions']:
            filters = filters + "--filter='+ **%s' " % exception
        filters = filters + "--filter='+ **%s' " % os.path.dirname(exception)
    return rsync(config['src'],config['dst'],filters)

#main
cfg = initConfig()
configs = cfg.get_config()
for config in configs.keys():
    sync(configs[config])
