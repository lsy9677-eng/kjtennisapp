import test from 'node:test';
import assert from 'node:assert/strict';
import {isolatedToolEnvironment} from '../dev/prepare-pages.mjs';
test('isolated tool environment preserves Windows Path and Linux PATH without leaking credentials',()=>{
    for(const key of ['Path','PATH']){
        const source={[key]:'synthetic-repository-tools',SAMPLE_TOKEN:'synthetic-secret',NODE_OPTIONS:'unsafe-preload'};
        const result=isolatedToolEnvironment(source);
        assert.ok(result.PATH.endsWith('synthetic-repository-tools'));
        assert.equal(Object.keys(result).filter(key=>key.toUpperCase()==='PATH').length,1);
        assert.equal(result.SAMPLE_TOKEN,undefined);assert.match(result.NODE_OPTIONS,/offline-network/);
        assert.equal(source[key],'synthetic-repository-tools');
    }
});
