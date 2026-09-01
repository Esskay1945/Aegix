import React, { useRef, useMemo, useEffect } from 'react';
import { Canvas, useFrame, extend } from '@react-three/fiber';
import { OrbitControls, Effects } from '@react-three/drei';
import { UnrealBloomPass } from 'three-stdlib';
import * as THREE from 'three';

extend({ UnrealBloomPass });

const ParticleSwarm = () => {
  const meshRef = useRef();
  const count = 50000;
  const speedMult = 0.8;
  const dummy = useMemo(() => new THREE.Object3D(), []);
  const target = useMemo(() => new THREE.Vector3(), []);
  const pColor = useMemo(() => new THREE.Color(), []);
  const color = pColor; // Alias for user code compatibility
  
  const positions = useMemo(() => {
     const pos = [];
     for(let i=0; i<count; i++) pos.push(new THREE.Vector3((Math.random()-0.5)*100, (Math.random()-0.5)*100, (Math.random()-0.5)*100));
     return pos;
  }, []);

  // Material & Geom
  const material = useMemo(() => new THREE.MeshBasicMaterial({ color: 0xffffff }), []);
  const geometry = useMemo(() => new THREE.TetrahedronGeometry(0.25), []);

  const PARAMS = useMemo(() => ({"scale":55,"rotation":0.8,"chaos":0.7}), []);
  const addControl = (id, l, min, max, val) => {
      return PARAMS[id] !== undefined ? PARAMS[id] : val;
  };
  const setInfo = () => {};
  const annotate = () => {};

  useFrame((state) => {
    if (!meshRef.current) return;
    const time = state.clock.getElapsedTime() * speedMult;
    const THREE_LIB = THREE;

    if(material.uniforms && material.uniforms.uTime) {
         material.uniforms.uTime.value = time;
    }

    for (let i = 0; i < count; i++) {
        // USER CODE START
        const scale = addControl("scale", "Reactor Size", 20, 100, 55);
        const rotation = addControl("rotation", "Rotation Speed", 0, 3, 0.8);
        const chaos = addControl("chaos", "Energy Chaos", 0, 2, 0.7);
        
        const u = i / count;
        const golden = 2.3999632297;
        const theta = i * golden;
        const y = 1 - 2 * u;
        const r = Math.sqrt(Math.max(0, 1 - y * y));
        const x = r * Math.cos(theta);
        const z = r * Math.sin(theta);
        
        const t = time * rotation;
        
        const ring = Math.floor(i % 7);
        const ringAngle = theta + t * (ring % 2 === 0 ? 1 : -1);
        const ringRadius = scale * (0.45 + ring * 0.075);
        
        const wave = Math.sin(theta * 9 + time * 3 + y * 12) * chaos;
        const outer = scale * (1 + wave * 0.045);
        
        let px = x * outer;
        let py = y * outer;
        let pz = z * outer;
        
        const core = Math.exp(-u * 18);
        px *= 1 - core * 0.35;
        py *= 1 - core * 0.35;
        pz *= 1 - core * 0.35;
        
        const ca = Math.cos(t * 0.7);
        const sa = Math.sin(t * 0.7);
        
        const rx = px * ca - pz * sa;
        const rz = px * sa + pz * ca;
        
        target.set(rx, py, rz);
        
        const pulse = 0.5 + 0.5 * Math.sin(time * 4 + theta * 3);
        const hue = 0.07 + pulse * 0.025;
        const light = 0.38 + pulse * 0.22;
        
        color.setHSL(hue, 1.0, light);
        
        if (i === 0) {
            setInfo("ARC REACTOR", "Holographic particle energy core");
        }
        // USER CODE END

        positions[i].lerp(target, 0.1);
        dummy.position.copy(positions[i]);
        dummy.updateMatrix();
        meshRef.current.setMatrixAt(i, dummy.matrix);
        meshRef.current.setColorAt(i, pColor);
    }
    meshRef.current.instanceMatrix.needsUpdate = true;
    if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true;
  });

  return (
    <instancedMesh ref={meshRef} args={[geometry, material, count]} />
  );
};

export default function App() {
  return (
    <div style={{ width: '100vw', height: '100vh', background: '#000' }}>
      <Canvas camera={{ position: [0, 0, 100], fov: 60 }}>
        <fog attach="fog" args={['#000000', 0.01]} />
        <ParticleSwarm />
        <OrbitControls autoRotate={true} />
        <Effects disableGamma>
            <unrealBloomPass threshold={0} strength={1.8} radius={0.4} />
        </Effects>
      </Canvas>
    </div>
  );
}