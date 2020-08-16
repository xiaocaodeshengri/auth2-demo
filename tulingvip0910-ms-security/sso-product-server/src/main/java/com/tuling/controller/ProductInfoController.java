package com.tuling.controller;

import com.tuling.entity.ProductInfo;
import com.tuling.mapper.ProductInfoMapper;
import com.tuling.vo.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Created by smlz on 2019/11/17.
 */
@RestController
@RequestMapping("/product")
public class ProductInfoController {


    @Autowired
    private ProductInfoMapper productInfoMapper;

    @RequestMapping("/selectProductInfoById/{productNo}")
    public Result<ProductInfo> selectProductInfoById(@PathVariable("productNo") String productNo) {

        ProductInfo productInfo = productInfoMapper.selectProductInfoById(productNo);
        return Result.success(productInfo);
    }


}
