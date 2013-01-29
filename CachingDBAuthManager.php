<?php
/**
 * CachingDBAuthManager class file.
 *
 * @author Muayyad Saleh Alsadi <alsadi@gmail.com>
 */
class CachingDbAuthManager extends CDbAuthManager {
    public $cacheID='cache';
    public $prefix='auth.';
    public $expires=86400; // a day;
    protected static $_items=false;
    protected static $_flat_items=false;
    protected static $_parents=false;

    public function checkAccess($itemName,$userId,$params=array())
    {
        $assignments=$this->getAuthAssignments($userId);
        if ($this->_checkAccessSingle($itemName,$userId,$params, $assignments))
            return true;
        $items=self::getParents();
        if (isset($items[$itemName])) {
            foreach($items[$itemName] as $item) {
                if ($this->_checkAccessSingle($item,$userId,$params, $assignments))
                    return true;
            }
        }
        return false;
    }


    public function purgeCache() {
        $this->getParents(false);
    }

    public function getAuthItem($name)
    {
        $this->getParents();
        if (isset(self::$_items[$name]))
            return self::$_items[$name];
        return null;
    }


    protected function _checkAccessSingle($itemName,$userId,$params,$assignments)
    {
                if(($item=$this->getAuthItem($itemName))===null)
                        return false;
                Yii::trace('Checking permission "'.$item->getName().'"','system.web.auth.CDbAuthManager');
                if($this->executeBizRule($item->getBizRule(),$params,$item->getData()))
                {
                        if(in_array($itemName,$this->defaultRoles))
                                return true;
                        if(isset($assignments[$itemName]))
                        {
                                $assignment=$assignments[$itemName];
                                if($this->executeBizRule($assignment->getBizRule(),$params,$assignment->getData()))
                                        return true;
                        }
                }
                return false;
    }


    public function getParents($use_cache=true) {
        $cache=Yii::app()->getComponent($this->cacheID);
        if ($use_cache) {
            if (self::$_flat_items!==false && self::$_items!==false && self::$_parents!==false)
                return self::$_parents;
            else {
                $items=$cache->get($this->prefix.'items');
                $children=$cache->get($this->prefix.'children');
                $parents=$cache->get($this->prefix.'parents');
                if ($children!==false && $items!==false && $parents!=false) {
                    self::$_items=$items;
                    self::$_parents=$parents;
                    self::$_flat_items=$children;
                    return self::$_parents;
                }
            }
        }
        $rows=$this->db->createCommand()
                    ->select('name, type, description, bizrule, data, parent')
                    ->from($this->itemTable)
                    ->leftJoin($this->itemChildTable, 'name=child')
                    ->queryAll();
        $items=array();
        $children=array();
        foreach($rows as $row)
        {
            if(($data=@unserialize($row['data']))===false)
            $data=null;
            $items[$row['name']]=new CAuthItem($this,$row['name'],$row['type'],$row['description'],$row['bizrule'],$data);
            if (!isset($children[$row['parent']])) $children[$row['parent']]=array();
            $children[$row['parent']][]=$row['name'];
        }
        foreach($children as $parent=>$item) {
            self::_recursive_flaten($children, $parent);
        }
        // FIXME: use array_unique on children and parents
        self::$_parents=array();
        foreach($children as $parent=>$a) {
            foreach($a as $item) {
                if (!isset(self::$_parents[$item])) self::$_parents[$item]=array($parent);
                else self::$_parents[$item][]=$parent;
            }
        }
        $cache->set($this->prefix.'items', $items, $this->expires);
        $cache->set($this->prefix.'children', $children, $this->expires);
        $cache->set($this->prefix.'parents', self::$_parents, $this->expires);
        self::$_items=$items;
        self::$_flat_items=$children;
         return self::$_parents;
    }

    protected static function _recursive_flaten(&$children, $parent) {
        if (!isset($children[$parent])) return;
        foreach($children[$parent] as $item) {
            if (isset($children[$item])) {
                foreach($children[$item] as $i) {
                    $children[$parent][]=$i;
                    self::_recursive_flaten($children, $i);
                }
            } else {
                $children[$item]=array();
            }
        }
    }

}