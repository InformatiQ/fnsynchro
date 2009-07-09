import os, commands, logging, time
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
            sections = ['system','general', object]
        else:
            sections = config.sections
        foo = {}
        for section in sections:
            bar = config[section]
            if section == 'general':
                general = {}
                for def_key in bar.iterkeys():
                    general[def_key] = bar.get(def_key)
            elif section == 'system':
                global system
                system = {}
                for def_key in bar.iterkeys():
                    system[def_key] = bar.get(def_key)
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

class lock:

    def __init__(self,system):
        self.lock_file = system['lock_file']
        self.wait_time = system['wait_time']
        self.wait_maxtime = system['wait_maxtime']

    def get_pid(self):
        return os.getpid()

    def get_lock(self):
        lockf = open(self.lock_file,'r')
        return lockf.read()

    def lock(self):
        pid = self.get_pid()
        lockf = open(self.lock_file,'w')
        lockf.write(str(pid))
        lockf.close()

    def unlock(self):
        if os.path.isfile(self.lock_file):
            os.remove(self.lock_file)

    def check(self):
        count = 1
        countmax = int(self.wait_maxtime)/int(self.wait_time)
        while os.path.isfile(self.lock_file):
            if count <= countmax:
                break
            lock_pid = self.get_lock()
            cmd = "ps aux|grep %s | grep FNSynchro.py | wc -l" %lock_pid
            print cmd
            running_pids = commands.getoutput(cmd) 
            if int(running_pids) != 1:
                log.info("removing stale lock file")
                break
            else:
                time.sleep()
                count = count + 1
        self.unlock()

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

class access():
    CO = ['Music', 'Documents', 'A_Posteriori']
    def walktree (top = ".", depthfirst = True, hidden = False, dir_only = False):
        names = os.listdir(top)
        if not depthfirst:
            yield top, names
        for name in names:
            try:
                if not hidden and name.startswith('.'):
                    continue
                st = os.lstat(os.path.join(top, name))
            except os.error:
                continue
            if stat.S_ISDIR(st.st_mode):
                if dir_only:
                    yield top, names
                for (newtop, children) in walktree (os.path.join(top, name), depthfirst):
                    yield newtop, children
        if depthfirst:
            yield top, names

    def access_locations_list():
        for (basepath, children) in self.walktree("/home/rhanna/",False):
            for child in children:
                curdir = os.path.join(basepath, child)
                if child in CO:
                    print 'create htaccess in %s' % curdir
#main
cfg = initConfig()
configs = cfg.get_config()
l = lock(system)
l.check()
l.lock()
for config in configs.keys():
    print configs[config]['pattern']
#    if not sync(configs[config]):
#        log.error('sync failed')
l.unlock
